//! Plano de discagem por peer — como aquela central apresenta os números.
//!
//! Esta é a peça mais carregadora do desenho, e a razão está medida: **20,3% dos destinos
//! do corpus de produção não resolvem a país sem despelamento**, e país é a única feature
//! comportamental que sobreviveu à medição (`SPEC.md` §4). Errar aqui não degrada uma
//! feature secundária — degrada a única que existe.
//!
//! O despelamento também é o **primeiro filtro do caminho quente**: o que não casa nenhum
//! prefixo não é internacional para aquela central, sai de escopo e passa sem canonicalizar.
//! Numa operadora de tráfego majoritariamente doméstico, é por aqui que a maioria das
//! chamadas sai — e é o que faz o custo escalar com o volume internacional em vez do total.

/// Comprimento máximo de um E.164, sem o `+` (ITU-T E.164 §6.2.1).
const E164_MAX_DIGITS: usize = 15;

/// Menor comprimento plausível para número internacional (código de país + assinante).
/// Serve de porteiro barato antes da validação real; não pretende ser exato.
const E164_MIN_DIGITS: usize = 7;

/// Como uma central apresenta os números que envia.
///
/// Declarado no JSON e **aprendido em paralelo** — a discordância entre os dois é alarme,
/// não detalhe (`SPEC.md` §4): prefixo a mais é inofensivo, **prefixo faltando é grave e
/// silencioso**, porque a chamada internacional escapa do sistema inteiro e nada acusa.
#[derive(Debug, Clone, Default)]
pub struct DialPlan {
    /// Prefixos de discagem internacional, ex.: `["+", "011", "9011", "00"]`.
    /// A ordem é irrelevante: o casamento é sempre pelo **mais longo**.
    prefixes: Vec<String>,
    /// A central envia E.164 puro, sem prefixo algum — comum em wholesale.
    ///
    /// É um sinalizador explícito, e não um prefixo vazio na lista, porque a semântica é
    /// perigosa: com ele ligado, `2125551234` é Marrocos; sem ele, é um número nacional
    /// dos EUA. Exigir a declaração explícita evita ligar isso sem perceber.
    bare_e164: bool,
}

/// O que sobrou depois de tirar o prefixo internacional: código do país mais assinante,
/// em dígitos, sem `+`. Ainda **não validado** contra plano de numeração.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternationalDigits(pub String);

impl DialPlan {
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            bare_e164: false,
        }
    }

    /// Declara que a central envia E.164 puro. Ver o campo `bare_e164`.
    pub fn with_bare_e164(mut self) -> Self {
        self.bare_e164 = true;
        self
    }

    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// Decide se a string discada é internacional para esta central e devolve os dígitos.
    ///
    /// `None` significa **fora de escopo, passa** — não é falha e nunca é motivo de
    /// bloqueio. Repetir o `R07` do TFPS Java, que negava tudo que não classificava e
    /// virou 39% de todas as rejeições, é o erro que esta função existe para evitar.
    pub fn to_international(&self, dialed: &str) -> Option<InternationalDigits> {
        let cleaned = strip_visual_separators(dialed);

        // Casamento pelo mais longo. Resolve sozinho a ambiguidade clássica: central com
        // `0` para tronco nacional e `00` para internacional produz `0212…` nacional e
        // `00212…` internacional, sem regra extra.
        let best = self
            .prefixes
            .iter()
            .filter(|p| !p.is_empty() && cleaned.starts_with(p.as_str()))
            .max_by_key(|p| p.len());

        let rest = match best {
            Some(p) => &cleaned[p.len()..],
            None if self.bare_e164 => cleaned.as_str(),
            None => return None,
        };

        let digits: String = rest.chars().filter(char::is_ascii_digit).collect();
        if rest.chars().any(|c| !c.is_ascii_digit()) {
            // Sobrou algo que não é dígito depois do prefixo: não é número discável.
            return None;
        }
        if !(E164_MIN_DIGITS..=E164_MAX_DIGITS).contains(&digits.len()) {
            return None;
        }
        Some(InternationalDigits(digits))
    }

    /// A string discada casa algum prefixo declarado? Porteiro barato do caminho quente,
    /// sem alocar nada — usado para descartar tráfego doméstico antes de qualquer trabalho.
    pub fn looks_international(&self, dialed: &str) -> bool {
        if self.bare_e164 {
            return true;
        }
        self.prefixes
            .iter()
            .any(|p| !p.is_empty() && dialed.starts_with(p.as_str()))
    }
}

/// Remove separadores visuais que aparecem em Request-URI real: `-`, `.`, espaço,
/// parênteses. O `+` é preservado, porque é prefixo e não separador.
fn strip_visual_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plano() -> DialPlan {
        DialPlan::new(["+", "00", "011", "9011"])
    }

    #[test]
    fn casa_pelo_prefixo_mais_longo() {
        let p = plano();
        // `9011` vence `011`, que venceria `0` se existisse.
        assert_eq!(
            p.to_international("9011252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("011252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("00252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("+252612345678").unwrap().0,
            "252612345678"
        );
    }

    #[test]
    fn a_ambiguidade_classica_do_zero_resolve_sozinha() {
        // Central com `0` para tronco nacional e `00` para internacional.
        let p = DialPlan::new(["0", "00"]);
        // Nacional: `0` é o prefixo mais longo que casa, e o resto é curto demais
        // para ser internacional plausível — ainda assim é o comportamento a fixar.
        assert_eq!(
            p.to_international("00212555123456").unwrap().0,
            "212555123456"
        );
        // Com `0` só, o que sobra ainda é aceito como dígitos; é o caso "prefixo a mais",
        // que o SPEC classifica como inofensivo — não canonicaliza para país válido depois.
        assert!(p.to_international("0212555123456").is_some());
    }

    #[test]
    fn fora_de_escopo_devolve_none_e_nunca_bloqueia() {
        let p = plano();
        assert!(p.to_international("2005").is_none(), "ramal interno");
        assert!(p.to_international("911").is_none(), "código de serviço");
        assert!(
            p.to_international("5511999998888").is_none(),
            "nacional sem prefixo"
        );
    }

    #[test]
    fn e164_puro_exige_declaracao_explicita() {
        let sem = DialPlan::new(Vec::<String>::new());
        assert!(sem.to_international("252612345678").is_none());

        let com = DialPlan::new(Vec::<String>::new()).with_bare_e164();
        assert_eq!(
            com.to_international("252612345678").unwrap().0,
            "252612345678"
        );
    }

    #[test]
    fn separadores_visuais_sao_removidos() {
        let p = plano();
        assert_eq!(
            p.to_international("+55 (11) 99999-8888").unwrap().0,
            "5511999998888"
        );
    }

    #[test]
    fn recusa_o_que_nao_e_discavel() {
        let p = plano();
        assert!(
            p.to_international("+55abc999998888").is_none(),
            "letras no meio"
        );
        assert!(p.to_international("+1234").is_none(), "curto demais");
        assert!(
            p.to_international("+1234567890123456789").is_none(),
            "passa de E.164"
        );
    }

    #[test]
    fn porteiro_barato_nao_aloca_e_concorda_com_o_despelamento() {
        let p = plano();
        assert!(p.looks_international("9011252612345678"));
        assert!(!p.looks_international("2005"));
    }
}
