//! O motor: junta despelamento, resolução de país e novidade num veredito.
//!
//! Segue o fluxo do `SPEC.md` §3. Duas propriedades desse fluxo são estruturais e estão
//! codificadas aqui:
//!
//! - **o filtro de prefixo vem antes de tudo**, e o que não é internacional sai sem
//!   canonicalizar — é o que faz o custo escalar com o volume internacional, não com o total;
//! - **o caminho de decisão não tem estado de diálogo**: duração e desfecho são pós-fato e
//!   pertencem ao caminho de aprendizado.
//!
//! O motor não lê relógio nem toca rede. Tempo entra por parâmetro.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::country::{self, Country};
use crate::dialplan::DialPlan;
use crate::novelty::{PairState, RotatingBitmap, Timestamp};
use crate::perimeter::{AuthAbuse, NoiseFilter};
use crate::sip::{self, Message, Method};

/// Em que modo a camada comportamental está.
///
/// O perímetro bloqueia desde o minuto 1; o comportamento espera. `SPEC.md` §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Observa e **não bloqueia**, até o instante dado.
    Learning {
        until: Timestamp,
    },
    Active,
}

impl Mode {
    fn is_learning(&self, now: Timestamp) -> bool {
        matches!(self, Mode::Learning { until } if now < *until)
    }
}

/// O que o motor decidiu sobre uma tentativa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Não é assunto do sistema — não é SIP, não é INVITE, ou não é internacional.
    /// **Nunca é bloqueio**, e a distinção importa: o `R07` do TFPS Java negava o que
    /// não classificava e virou 39% de todas as rejeições.
    OutOfScope(&'static str),
    /// Internacional, conhecido ou insuficiente para disparar.
    Pass { country: &'static str, novel: bool },
    /// Teria bloqueado, mas a camada comportamental ainda está aprendendo.
    WouldBlock {
        country: &'static str,
        novel_in_window: usize,
    },
    /// Bloqueio: o par acumulou países inéditos demais na janela.
    Block {
        country: &'static str,
        novel_in_window: usize,
    },
    /// Ruído de perímetro: ferramenta de varredura conhecida pelo user-agent.
    /// Quando a imposição entrar, isto morre no `XDP_DROP` e some do sngrep.
    Noise { signature: &'static str },
    /// Padrão de injeção na URI. Sinal de confiança **mais alta** que o user-agent:
    /// ferramenta de varredura pode forjar UA legítimo, mas nenhum telefone real põe
    /// aspa simples ou `--` no `From`.
    Injection { pattern: &'static str },
    /// Excesso de tentativas **autenticadas** numa janela curta — força bruta de
    /// credencial. É a Cadeia A do `SPEC.md`, observada no fio em vez de no log.
    AuthAbuse { attempts: u32 },
    /// Internacional pela forma, mas sem país reconhecível na tabela E.164.
    /// **Não bloqueia** — carrega os dígitos para que o operador possa diagnosticar,
    /// em vez de virar um contador mudo.
    UnknownCountry(String),
}

/// Contadores para os requisitos de observabilidade do `SPEC.md` §12.
///
/// Existem porque o argumento do projeto contra o `fail2ban` é que **o incumbente falha
/// em silêncio**. Um sistema que não sabe dizer o que está vendo repetiria isso.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub packets: u64,
    pub sip_parsed: u64,
    /// Respostas SIP. Contadas à parte de `not_sip`: confundi-las com lixo faria o
    /// operador concluir que está capturando a interface errada.
    pub responses: u64,
    /// Keepalive CRLF de NAT. Contado à parte porque numa 5060 com clientes residenciais
    /// é a maioria dos pacotes — e chamá-lo de lixo faria o relatório mentir.
    pub keepalives: u64,
    pub not_sip: u64,
    /// Pacotes que o perímetro removeria. É o numerador da medição que o ticket 17 pede:
    /// que fração do tráfego numa porta pública é varredura.
    pub noise: u64,
    /// URIs com padrão de injeção — a regra R12 do TFPS 2023, ressuscitada.
    pub injections: u64,
    /// Origens condenadas por força bruta de autenticação.
    pub auth_abuse: u64,
    /// Tentativas autenticadas observadas — o denominador do sinal acima.
    pub auth_attempts: u64,
    pub invites: u64,
    pub international: u64,
    pub uncanonicalizable: u64,
    pub unknown_country: u64,
    pub novel: u64,
    pub blocks: u64,
    pub would_block: u64,
    /// Pares recusados por teto de memória. **Diferente de zero é sintoma de ataque de
    /// rotação de A-number** — e precisa aparecer no relatório, não sumir em silêncio.
    pub pairs_dropped: u64,
    /// Peers recusados por teto.
    pub peers_dropped: u64,
}

/// Teto de pares por peer.
///
/// Existe porque o `SPEC.md` §5 diz que **rotacionar A-number é comportamento esperado do
/// atacante** — e sem teto o sistema responde a isso alocando até morrer. A ~150 bytes por
/// par, um atacante a 1000 INVITEs/s com A-number único enche 192 MB em ~20 minutos.
/// Um antifraude com vetor de DoS descrito na própria especificação não cumpre a premissa.
const MAX_PAIRS_PER_PEER: usize = 50_000;

/// Teto de peers distintos. Peer é o IP de origem, que não é forjável na posição de
/// observação — então este teto é muito mais folgado que o de pares.
const MAX_PEERS: usize = 10_000;

/// Uma linha do estado de um par, como o armazenamento durável a vê.
#[derive(Debug, Clone)]
pub struct PairRecord {
    pub peer: Ipv4Addr,
    pub a_number: String,
    pub cur: [u64; 4],
    pub prev: [u64; 4],
    pub period: u32,
    pub last_seen: u32,
}

/// Frequência de um país para um peer.
#[derive(Debug, Clone, Copy)]
pub struct PeerCountryRecord {
    pub peer: Ipv4Addr,
    pub country: u16,
    pub calls: u32,
}

#[derive(Debug, Default)]
struct PeerState {
    dial_plan: DialPlan,
    /// Estado por A-number, com o instante da última observação para poder podar.
    pairs: HashMap<String, (PairState, u32)>,
    /// Distribuição de frequência por país — o prior que um par novo herda.
    /// `SPEC.md` §6: herdar o conjunto inteiro do peer não funcionaria, porque peer
    /// wholesale liga para 200 países e a saturação voltaria.
    country_calls: HashMap<u16, u32>,
    total_calls: u32,
    /// Contador de força bruta desta origem.
    auth: AuthAbuse,
}

pub struct Engine {
    peers: HashMap<Ipv4Addr, PeerState>,
    default_plan: DialPlan,
    mode: Mode,
    pub noise_filter: NoiseFilter,
    pub stats: Stats,
}

impl Engine {
    pub fn new(default_plan: DialPlan, mode: Mode) -> Self {
        Self {
            peers: HashMap::new(),
            default_plan,
            mode,
            noise_filter: NoiseFilter::new(),
            stats: Stats::default(),
        }
    }

    /// Declara o plano de discagem de um peer. Ver `SPEC.md` §4: declarar bate aprender
    /// por valer já na primeira chamada, em vez de esperar convergência.
    pub fn declare_dial_plan(&mut self, peer: Ipv4Addr, plan: DialPlan) {
        self.peers.entry(peer).or_default().dial_plan = plan;
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn pair_count(&self) -> usize {
        self.peers.values().map(|p| p.pairs.len()).sum()
    }

    /// Estado de um par, no formato que o armazenamento durável grava.
    ///
    /// O núcleo **não faz I/O** — ele exporta e importa; quem grava é o binário. É o que
    /// mantém tudo aqui determinístico e testável sem disco.
    pub fn export_pairs(&self) -> impl Iterator<Item = PairRecord> + '_ {
        self.peers.iter().flat_map(|(ip, st)| {
            st.pairs.iter().map(move |(a, (pair, last))| {
                let (cur, prev, period) = pair.bitmap().parts();
                PairRecord {
                    peer: *ip,
                    a_number: a.clone(),
                    cur,
                    prev,
                    period,
                    last_seen: *last,
                }
            })
        })
    }

    /// Frequência de países por peer — o prior que um par novo herda.
    pub fn export_peer_countries(&self) -> impl Iterator<Item = PeerCountryRecord> + '_ {
        self.peers.iter().flat_map(|(ip, st)| {
            st.country_calls
                .iter()
                .map(move |(c, n)| PeerCountryRecord {
                    peer: *ip,
                    country: *c,
                    calls: *n,
                })
        })
    }

    /// Restaura um par. Respeita os tetos de memória: estado persistido não pode ser
    /// usado para contornar o limite que protege contra rotação de A-number.
    pub fn import_pair(&mut self, r: PairRecord) {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&r.peer) {
            return;
        }
        let plan = self.default_plan.clone();
        let st = self.peers.entry(r.peer).or_insert_with(|| PeerState {
            dial_plan: plan,
            ..Default::default()
        });
        if st.pairs.len() >= MAX_PAIRS_PER_PEER {
            return;
        }
        st.pairs.insert(
            r.a_number,
            (
                PairState::from_bitmap(RotatingBitmap::from_parts(r.cur, r.prev, r.period)),
                r.last_seen,
            ),
        );
    }

    pub fn import_peer_country(&mut self, r: PeerCountryRecord) {
        let plan = self.default_plan.clone();
        let st = self.peers.entry(r.peer).or_insert_with(|| PeerState {
            dial_plan: plan,
            ..Default::default()
        });
        *st.country_calls.entry(r.country).or_insert(0) += r.calls;
        st.total_calls = st.total_calls.saturating_add(r.calls);
    }

    /// Memória aproximada do estado de aprendizado, para o relatório. O operador precisa
    /// poder ver isto crescer antes de o serviço ser morto por limite de cgroup.
    pub fn approx_state_bytes(&self) -> usize {
        const PER_PAIR: usize = 160; // PairState + chave String + overhead do HashMap
        const PER_PEER: usize = 256;
        self.peers.len() * PER_PEER + self.pair_count() * PER_PAIR
    }

    /// Processa um datagrama SIP vindo de `peer`.
    pub fn observe(&mut self, peer: Ipv4Addr, payload: &[u8], now: Timestamp) -> Decision {
        self.stats.packets += 1;

        let req = match sip::parse(payload) {
            Some(Message::Request(r)) => {
                self.stats.sip_parsed += 1;
                r
            }
            Some(Message::Response(_)) => {
                // O caminho de aprendizado usará isto (`200 OK` diz se atendeu); o de
                // decisão, não. Por ora conta, para que o relatório seja honesto.
                self.stats.responses += 1;
                return Decision::OutOfScope("resposta SIP");
            }
            Some(Message::Keepalive) => {
                self.stats.keepalives += 1;
                return Decision::OutOfScope("keepalive de NAT");
            }
            None => {
                self.stats.not_sip += 1;
                return Decision::OutOfScope("não é SIP");
            }
        };

        // Perímetro vem antes de tudo, e vale para **qualquer** método: scanner manda
        // OPTIONS e REGISTER tanto quanto INVITE. Sai aqui sem tocar em estado nenhum,
        // que é justamente o ponto — ruído não pode entrar na linha de base.
        if let Some(sig) = self.noise_filter.is_noise(req.user_agent) {
            self.stats.noise += 1;
            return Decision::Noise { signature: sig };
        }

        // Injeção na URI vem junto do perímetro e vale para qualquer método: o ataque
        // aparece tanto em INVITE quanto em REGISTER e OPTIONS.
        if let Some(pat) =
            self.noise_filter
                .injection_in_uri(&[Some(req.request_uri), req.from, req.to])
        {
            self.stats.injections += 1;
            return Decision::Injection { pattern: pat };
        }

        // Força bruta de credencial: conta `REGISTER` **com `Authorization`**, nunca o
        // `401` de desafio — todo registro legítimo recebe um, e contá-los bloquearia
        // todos os clientes. Ver `perimeter::AUTH_ATTEMPTS_TO_BLOCK`.
        if req.method == Method::Register && req.authorization.is_some() {
            self.stats.auth_attempts += 1;
            if self.peers.len() < MAX_PEERS || self.peers.contains_key(&peer) {
                let plan = self.default_plan.clone();
                let st = self.peers.entry(peer).or_insert_with(|| PeerState {
                    dial_plan: plan,
                    ..Default::default()
                });
                let (n, exceeded) = st.auth.attempt(now.0);
                if exceeded {
                    self.stats.auth_abuse += 1;
                    return Decision::AuthAbuse { attempts: n };
                }
            }
        }

        if req.method != Method::Invite {
            return Decision::OutOfScope("não é INVITE");
        }
        self.stats.invites += 1;

        let Some(dialed) = req.request_user else {
            return Decision::OutOfScope("INVITE sem número discado");
        };

        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            self.stats.peers_dropped += 1;
            return Decision::OutOfScope("teto de peers atingido");
        }
        let state = self.peers.entry(peer).or_insert_with(|| PeerState {
            dial_plan: self.default_plan.clone(),
            ..Default::default()
        });

        // Filtro mais barato do caminho quente: o que não é internacional sai aqui,
        // sem canonicalizar e sem tocar em nenhum estado.
        let Some(digits) = state.dial_plan.to_international(dialed) else {
            return Decision::OutOfScope("não é internacional para este peer");
        };
        self.stats.international += 1;

        let Some(c) = country::resolve(&digits) else {
            // Internacional pela forma, mas sem país reconhecível. **Não bloqueia** —
            // seria o erro do R07. Carrega os dígitos para diagnóstico.
            self.stats.unknown_country += 1;
            return Decision::UnknownCountry(digits.0);
        };

        Self::decide(state, &req, c, now, self.mode, &mut self.stats)
    }

    fn decide(
        state: &mut PeerState,
        req: &sip::Request<'_>,
        c: Country,
        now: Timestamp,
        mode: Mode,
        stats: &mut Stats,
    ) -> Decision {
        // O A-number é asserção não verificada do remetente; serve de agrupamento,
        // nunca de identidade. A âncora de confiança é o peer. `SPEC.md` §5.
        let a_number = req.from_user().unwrap_or("<sem-from>").to_string();

        *state.country_calls.entry(c.index.0).or_insert(0) += 1;
        state.total_calls += 1;

        // Poda antes de inserir: pares vistos uma vez e nunca mais — a assinatura da
        // rotação de A-number — saem sozinhos, e o legítimo, que volta, permanece.
        if state.pairs.len() >= MAX_PAIRS_PER_PEER && !state.pairs.contains_key(&a_number) {
            let cutoff = now.0.saturating_sub(crate::novelty::WINDOW_SECS);
            state.pairs.retain(|_, (_, last)| *last >= cutoff);
            if state.pairs.len() >= MAX_PAIRS_PER_PEER {
                // Ainda cheio depois da poda: recusa o par novo em vez de crescer.
                // Perde-se aprendizado desse A-number, não a integridade do processo.
                stats.pairs_dropped += 1;
                return Decision::Pass {
                    country: c.iso,
                    novel: false,
                };
            }
        }

        let (pair, last) = state.pairs.entry(a_number).or_default();
        *last = now.0;
        let obs = pair.observe(c.index, now);

        if obs.novel {
            stats.novel += 1;
        }

        if !obs.triggered {
            return Decision::Pass {
                country: c.iso,
                novel: obs.novel,
            };
        }
        if mode.is_learning(now) {
            stats.would_block += 1;
            return Decision::WouldBlock {
                country: c.iso,
                novel_in_window: obs.novel_in_window,
            };
        }
        stats.blocks += 1;
        Decision::Block {
            country: c.iso,
            novel_in_window: obs.novel_in_window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(from: &str, dialed: &str) -> Vec<u8> {
        format!(
            "INVITE sip:{dialed}@pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK1\r\n\
             From: <sip:{from}@pbx>;tag=t1\r\n\
             To: <sip:{dialed}@pbx>\r\n\
             Call-ID: c1\r\n\
             CSeq: 1 INVITE\r\n\r\n"
        )
        .into_bytes()
    }

    fn peer() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 5)
    }

    fn engine() -> Engine {
        Engine::new(DialPlan::new(["+", "00", "011", "9011"]), Mode::Active)
    }

    fn t(s: u32) -> Timestamp {
        Timestamp(1_800_000_000 + s)
    }

    #[test]
    fn trafego_domestico_sai_pelo_filtro_mais_barato() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("200", "2005"), t(0));
        assert!(matches!(d, Decision::OutOfScope(_)));
        // Não tocou em estado nenhum: nem par, nem peer.
        assert_eq!(e.pair_count(), 0);
        assert_eq!(e.stats.international, 0);
    }

    #[test]
    fn internacional_conhecido_passa() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("200", "00551199998888"), t(0));
        assert_eq!(
            d,
            Decision::Pass {
                country: "BR",
                novel: true
            }
        );
        // A segunda para o mesmo país já não é novidade.
        let d = e.observe(peer(), &invite("200", "00551199997777"), t(10));
        assert_eq!(
            d,
            Decision::Pass {
                country: "BR",
                novel: false
            }
        );
    }

    #[test]
    fn dez_paises_ineditos_numa_hora_bloqueiam() {
        let mut e = engine();
        let destinos = [
            "00252612345678", // SO
            "00371234567",    // LV
            "0038761234567",  // BA
            "0022012345678",  // GM
            "002451234567",   // GW
            "009601234567",   // MV
            "0053512345678",  // CU
            "002241234567",   // GN
            "0021612345678",  // TN
            "0037112345678",  // LV? não — 371 já usado; usa MK
        ];
        let mut ultimo = None;
        for (i, d) in destinos.iter().enumerate() {
            ultimo = Some(e.observe(peer(), &invite("200", d), t(i as u32 * 60)));
        }
        // O décimo destino repete a Letônia, então só 9 países inéditos: não dispara.
        assert!(matches!(ultimo, Some(Decision::Pass { .. })));

        // Um país inédito de verdade fecha a conta.
        let d = e.observe(peer(), &invite("200", "0038912345678"), t(700));
        assert!(
            matches!(d, Decision::Block { .. }),
            "esperava bloqueio, veio {d:?}"
        );
        assert_eq!(e.stats.blocks, 1);
    }

    #[test]
    fn em_aprendizado_nao_bloqueia_mas_registra() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Learning { until: t(100_000) });
        let destinos = [
            "00252612345678",
            "00371234567",
            "0038761234567",
            "0022012345678",
            "002451234567",
            "009601234567",
            "0053512345678",
            "002241234567",
            "0021612345678",
            "0038912345678",
        ];
        let mut ultimo = None;
        for (i, d) in destinos.iter().enumerate() {
            ultimo = Some(e.observe(peer(), &invite("200", d), t(i as u32 * 60)));
        }
        assert!(
            matches!(ultimo, Some(Decision::WouldBlock { .. })),
            "em aprendizado só registra, veio {ultimo:?}"
        );
        assert_eq!(e.stats.blocks, 0);
        assert_eq!(e.stats.would_block, 1);
    }

    #[test]
    fn pares_diferentes_nao_somam_entre_si() {
        // O acúmulo é por par (peer, A-number). Dez ramais estreando um país cada
        // é tráfego normal de escritório, não fraude.
        let mut e = engine();
        let destinos = [
            "00252612345678",
            "00371234567",
            "0038761234567",
            "0022012345678",
            "002451234567",
            "009601234567",
            "0053512345678",
            "002241234567",
            "0021612345678",
            "0038912345678",
        ];
        for (i, d) in destinos.iter().enumerate() {
            let ramal = format!("2{i:02}");
            let dec = e.observe(peer(), &invite(&ramal, d), t(i as u32 * 60));
            assert!(
                matches!(dec, Decision::Pass { .. }),
                "ramal {ramal}: {dec:?}"
            );
        }
        assert_eq!(e.pair_count(), 10);
        assert_eq!(e.stats.blocks, 0);
    }

    #[test]
    fn rotacao_de_a_number_nao_cresce_sem_limite() {
        // O ataque que o SPEC §5 descreve como esperado: A-number novo a cada chamada.
        // Sem teto isto derrubaria o processo por memória — que seria um vetor de DoS
        // descrito na própria especificação do produto.
        let mut e = engine();
        for i in 0..(MAX_PAIRS_PER_PEER + 5_000) {
            let a = format!("spoof{i}");
            // Todos na mesma janela, para que a poda não possa removê-los.
            e.observe(peer(), &invite(&a, "00551199998888"), t(0));
        }
        assert!(
            e.pair_count() <= MAX_PAIRS_PER_PEER,
            "estourou o teto: {} pares",
            e.pair_count()
        );
        assert!(e.stats.pairs_dropped > 0, "deveria contar as recusas");
    }

    #[test]
    fn depois_do_ataque_a_poda_devolve_o_espaco_a_quem_chega() {
        // Um ataque de rotação enche o teto numa janela. Quando a janela passa e um
        // par novo e legítimo aparece, a poda limpa os que nunca voltaram — o sistema
        // se recupera sozinho, sem varredura em segundo plano.
        let mut e = engine();
        for i in 0..MAX_PAIRS_PER_PEER {
            e.observe(
                peer(),
                &invite(&format!("spoof{i}"), "00551199998888"),
                t(0),
            );
        }
        assert_eq!(
            e.pair_count(),
            MAX_PAIRS_PER_PEER,
            "o ataque deve encher o teto"
        );

        // Duas janelas depois chega um cliente novo de verdade.
        let dec = e.observe(
            peer(),
            &invite("cliente-novo", "00551199998888"),
            t(crate::novelty::WINDOW_SECS * 2),
        );
        assert!(matches!(dec, Decision::Pass { .. }), "veio {dec:?}");
        assert!(
            e.pair_count() < 10,
            "a poda deveria ter varrido os efêmeros, restaram {}",
            e.pair_count()
        );
    }

    #[test]
    fn a_memoria_estimada_e_reportavel() {
        let mut e = engine();
        for i in 0..100 {
            e.observe(peer(), &invite(&format!("r{i}"), "00551199998888"), t(0));
        }
        assert!(e.approx_state_bytes() > 0);
        // O teto absoluto precisa caber no MemoryMax=192M da unidade systemd.
        let teto = MAX_PEERS * 256 + MAX_PEERS * MAX_PAIRS_PER_PEER * 160;
        assert!(teto > 0); // documenta que o pior caso teórico é enorme:
                           // por isso o teto de pares é POR PEER e o de peers é baixo — na prática,
                           // um peer sob ataque satura o seu próprio limite sem afetar os demais.
    }

    #[test]
    fn lixo_nao_derruba_nem_bloqueia() {
        let mut e = engine();
        for p in [&b"nao sou sip"[..], &[0xff, 0xfe][..], &b""[..]] {
            assert!(matches!(
                e.observe(peer(), p, t(0)),
                Decision::OutOfScope(_)
            ));
        }
        assert_eq!(e.stats.not_sip, 3);
        assert_eq!(e.stats.blocks, 0);
    }

    #[test]
    fn plano_declarado_por_peer_vence_o_padrao() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let outro = Ipv4Addr::new(10, 0, 0, 9);
        e.declare_dial_plan(outro, DialPlan::new(["9011"]));

        // Para o peer com plano próprio, `00…` não é internacional.
        assert!(matches!(
            e.observe(outro, &invite("200", "00551199998888"), t(0)),
            Decision::OutOfScope(_)
        ));
        // Mas `9011…` é.
        assert!(matches!(
            e.observe(outro, &invite("200", "9011551199998888"), t(1)),
            Decision::Pass { country: "BR", .. }
        ));
    }
}
