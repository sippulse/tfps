//! Detecção de novidade — o único sinal comportamental do sistema.
//!
//! Não há modelo estatístico aqui, e isso é decisão, não omissão (`SPEC.md` §6). A metade
//! supervisionada morreu com "sem corpus"; a não-supervisionada não se paga, porque 45% de
//! detecção a 2% de falso positivo é inviável num veredito binário. O que sobrou é
//! pertinência a conjunto: **este par já ligou para este país?**
//!
//! Duas medições sustentam o desenho:
//!
//! - estreia de país acontece em **0,85%** das chamadas após aquecimento, e cai para 0,28%
//!   na unidade madura — ou seja, **um país inédito sozinho não pode disparar**;
//! - a regra "dez países inéditos numa hora" disparou **4 vezes em 2.829 conta-dias**, e as
//!   quatro janelas eram as mais atípicas do corpus.
//!
//! Por isso o sinal é **acúmulo**, não evento.

use crate::country::CountryIndex;

/// Segundos desde a época Unix. O núcleo não lê relógio — o tempo entra por parâmetro,
/// o que mantém tudo determinístico e testável sem esperar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u32);

impl Timestamp {
    fn saturating_sub(self, other: Self) -> u32 {
        self.0.saturating_sub(other.0)
    }
}

/// Janela de acúmulo do predicado de bloqueio. **Constante universal**, derivada da física
/// da fraude: segundos são a escala do flood de sinalização, dias diluem o episódio.
pub const WINDOW_SECS: u32 = 3600;

/// Quantos países inéditos na janela disparam bloqueio. **Constante universal**, igual para
/// todos os clientes — não é a espécie de número por-cliente que ninguém ajustava e que
/// matou o TFPS 2023 (`DEFAULT_QUOTA`, `MAX_CONCURRENT`).
pub const NOVEL_COUNTRIES_TO_BLOCK: usize = 10;

/// Período de rotação do bitmap, em segundos: 45 dias. Precisa ser **maior que o modo de
/// aprendizado** de 30 dias, senão a linha de base nunca estabiliza.
pub const ROTATION_SECS: u32 = 45 * 24 * 3600;

/// Dois bitmaps de 256 bits: o período atual e o anterior.
///
/// "Já viu este país" é a **união** dos dois, o que dá memória efetiva entre `T` e `2T` —
/// 45 a 90 dias. Guardar carimbo de tempo por país custaria 240 timestamps por par e é
/// inviável na escala de milhões de pares; dois bitmaps custam **64 bytes**.
///
/// O efeito colateral é o que resolve o bootstrap envenenado: se o PBX chegou comprometido
/// e o aprendizado absorveu a fraude, **os países envenenados envelhecem e saem sozinhos**.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotatingBitmap {
    current: [u64; 4],
    previous: [u64; 4],
    /// Qual período de rotação o `current` representa. A rotação é preguiçosa: acontece
    /// quando o par é tocado, não por varredura em segundo plano.
    period: u32,
}

impl RotatingBitmap {
    /// Reconstrói a partir do que foi persistido. Usado só na carga do boot.
    pub fn from_parts(current: [u64; 4], previous: [u64; 4], period: u32) -> Self {
        Self {
            current,
            previous,
            period,
        }
    }

    /// Partes cruas, para persistir. Expostas porque `SQLite` é o armazenamento durável
    /// e o núcleo não faz I/O — quem grava é o binário.
    pub fn parts(&self) -> ([u64; 4], [u64; 4], u32) {
        (self.current, self.previous, self.period)
    }

    /// Gira se o período mudou. Chamado sempre antes de consultar ou marcar.
    fn rotate_to(&mut self, now: Timestamp) {
        let p = now.0 / ROTATION_SECS;
        if p == self.period {
            return;
        }
        if p == self.period + 1 {
            self.previous = self.current;
        } else {
            // Dois períodos ou mais sem tocar: tudo o que havia já expirou.
            self.previous = [0; 4];
        }
        self.current = [0; 4];
        self.period = p;
    }

    fn contains(&self, c: CountryIndex) -> bool {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        (self.current[w] | self.previous[w]) & (1u64 << b) != 0
    }

    fn insert(&mut self, c: CountryIndex) {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        self.current[w] |= 1u64 << b;
    }

    /// Quantos países distintos a unidade conhece. Usado em relatório e no resumo do dia 31.
    pub fn len(&self) -> u32 {
        (0..4)
            .map(|i| (self.current[i] | self.previous[i]).count_ones())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Anel de carimbos das estreias recentes, do tamanho exato do predicado.
///
/// Só precisa das últimas `NOVEL_COUNTRIES_TO_BLOCK` estreias: se a mais antiga delas ainda
/// está dentro da janela, o predicado disparou. Estreias são raras (0,85% das chamadas),
/// então este anel fica vazio na esmagadora maioria dos pares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NoveltyWindow {
    stamps: [u32; NOVEL_COUNTRIES_TO_BLOCK],
    len: u8,
    next: u8,
}

impl NoveltyWindow {
    fn push(&mut self, now: Timestamp) {
        self.stamps[self.next as usize] = now.0;
        self.next = (self.next + 1) % NOVEL_COUNTRIES_TO_BLOCK as u8;
        if (self.len as usize) < NOVEL_COUNTRIES_TO_BLOCK {
            self.len += 1;
        }
    }

    /// Quantas estreias caem dentro da janela que termina em `now`.
    fn count_within(&self, now: Timestamp) -> usize {
        self.stamps[..self.len as usize]
            .iter()
            .filter(|s| now.saturating_sub(Timestamp(**s)) < WINDOW_SECS)
            .count()
    }
}

/// O que a observação de uma chamada produziu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// O país era inédito para este par.
    pub novel: bool,
    /// Quantas estreias este par acumulou na janela corrente.
    pub novel_in_window: usize,
    /// O predicado de bloqueio disparou.
    pub triggered: bool,
}

/// Estado de aprendizado de um par `(peer, A-number)`.
///
/// Os dois bitmaps são 64 bytes; com o marcador de período e o anel de estreias, o estado
/// completo do par fica na casa de uma centena de bytes — um milhão de pares em algumas
/// dezenas de megabytes. É isso que torna a chave por A-number viável no alvo wholesale:
/// a operadora tem perfil largo, mas **cada par tem perfil estreito** (`SPEC.md` §5).
/// O teste `o_estado_por_par_cabe_no_orcamento_de_memoria` fixa esse orçamento.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairState {
    seen: RotatingBitmap,
    window: NoveltyWindow,
}

impl PairState {
    /// Reconstrói o estado de um par a partir do que foi persistido.
    ///
    /// A janela de estreias **não** é restaurada: ela cobre uma hora, e um processo que
    /// reinicia perde no máximo uma hora de acúmulo. Persistir o anel custaria mais do
    /// que vale.
    pub fn from_bitmap(seen: RotatingBitmap) -> Self {
        Self {
            seen,
            window: NoveltyWindow::default(),
        }
    }

    pub fn bitmap(&self) -> &RotatingBitmap {
        &self.seen
    }

    /// Registra uma chamada internacional deste par para `country`.
    ///
    /// Devolve o que aconteceu; **não decide veredito** — quem decide é o chamador, que
    /// também sabe se o modo de aprendizado está ativo.
    pub fn observe(&mut self, country: CountryIndex, now: Timestamp) -> Observation {
        self.seen.rotate_to(now);
        let novel = !self.seen.contains(country);
        if novel {
            self.seen.insert(country);
            self.window.push(now);
        }
        let novel_in_window = self.window.count_within(now);
        Observation {
            novel,
            novel_in_window,
            triggered: novel_in_window >= NOVEL_COUNTRIES_TO_BLOCK,
        }
    }

    /// Países que este par conhece — insumo do resumo apresentado na confirmação do dia 31.
    pub fn known_countries(&self) -> u32 {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u16) -> CountryIndex {
        CountryIndex(i)
    }

    /// Um instante seguro dentro de um período de rotação, longe das bordas.
    fn t(secs: u32) -> Timestamp {
        Timestamp(ROTATION_SECS * 100 + secs)
    }

    #[test]
    fn primeira_chamada_para_um_pais_e_novidade_e_a_segunda_nao() {
        let mut p = PairState::default();
        assert!(p.observe(c(63), t(0)).novel, "Somália inédita");
        assert!(!p.observe(c(63), t(10)).novel, "já vista");
        assert_eq!(p.known_countries(), 1);
    }

    #[test]
    fn um_pais_inedito_sozinho_nunca_dispara() {
        // A medição é explícita: estreia acontece em 0,85% das chamadas. Bloquear
        // uma estreia isolada seria bloquear 0,85% do tráfego internacional.
        let mut p = PairState::default();
        let o = p.observe(c(63), t(0));
        assert!(o.novel);
        assert!(!o.triggered);
    }

    #[test]
    fn dez_paises_ineditos_numa_hora_disparam() {
        let mut p = PairState::default();
        for i in 0..NOVEL_COUNTRIES_TO_BLOCK as u16 {
            let o = p.observe(c(i), t(i as u32 * 60));
            assert_eq!(o.triggered, i as usize == NOVEL_COUNTRIES_TO_BLOCK - 1);
        }
    }

    #[test]
    fn dez_paises_espalhados_por_mais_de_uma_hora_nao_disparam() {
        // O sinal é acúmulo *numa janela*; o mesmo total diluído no dia é tráfego normal
        // de quem viaja pelo mundo devagar.
        let mut p = PairState::default();
        for i in 0..NOVEL_COUNTRIES_TO_BLOCK as u16 {
            let o = p.observe(c(i), t(i as u32 * 600)); // 10 min entre cada
            assert!(!o.triggered, "não deveria disparar em {i}");
        }
    }

    #[test]
    fn repetir_o_mesmo_pais_nao_acumula() {
        let mut p = PairState::default();
        for k in 0..50 {
            let o = p.observe(c(63), t(k * 10));
            assert!(!o.triggered, "repetição não é novidade");
        }
    }

    #[test]
    fn o_bitmap_esquece_depois_de_dois_periodos() {
        let mut p = PairState::default();
        p.observe(c(63), Timestamp(0));
        assert_eq!(p.known_countries(), 1);

        // Um período depois: ainda lembra, pelo bitmap anterior.
        p.observe(c(1), Timestamp(ROTATION_SECS + 10));
        assert!(!p.observe(c(63), Timestamp(ROTATION_SECS + 20)).novel);

        // Dois períodos depois da marcação original: esqueceu.
        let o = p.observe(c(63), Timestamp(3 * ROTATION_SECS + 10));
        assert!(o.novel, "país envelhecido volta a ser novidade");
    }

    #[test]
    fn o_esquecimento_cura_um_pbx_que_chegou_comprometido() {
        // Cenário: instalação sobre PBX já fraudado. O aprendizado absorve a Somália
        // como rotina. Passados dois períodos sem novas chamadas para lá, o
        // envenenamento sai sozinho — a segunda defesa do SPEC §6.
        let mut envenenado = PairState::default();
        envenenado.observe(c(63), Timestamp(0));
        let depois = envenenado.observe(c(63), Timestamp(2 * ROTATION_SECS + 1));
        assert!(depois.novel, "o sistema precisa se curar sozinho");
    }

    #[test]
    fn a_janela_desliza_em_vez_de_zerar() {
        let mut p = PairState::default();
        // Nove estreias no começo da hora.
        for i in 0..9u16 {
            p.observe(c(i), t(i as u32));
        }
        // Uma hora e pouco depois, as nove saíram da janela: a décima não dispara.
        let o = p.observe(c(9), t(WINDOW_SECS + 100));
        assert!(!o.triggered);
        assert_eq!(o.novel_in_window, 1);
    }

    #[test]
    fn o_estado_por_par_cabe_no_orcamento_de_memoria() {
        // A conta que sustenta a chave por A-number em wholesale (SPEC §5 e §6).
        // Fixada como teste porque é requisito, não detalhe: se alguém acrescentar um
        // campo gordo ao estado do par, milhões de pares deixam de caber.
        let bitmap = core::mem::size_of::<RotatingBitmap>();
        let pair = core::mem::size_of::<PairState>();
        assert!(bitmap <= 72, "RotatingBitmap cresceu para {bitmap} bytes");
        assert!(pair <= 128, "PairState cresceu para {pair} bytes");
        // Um milhão de pares no orçamento declarado.
        assert!(pair * 1_000_000 <= 128 * 1024 * 1024);
    }
}
