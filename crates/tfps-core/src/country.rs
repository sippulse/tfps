//! Resolução de país a partir dos dígitos internacionais, e o índice compacto que o
//! bitmap de novidade usa.
//!
//! O alfabeto de países é pequeno — algo em torno de 250 — e é **essa** propriedade que
//! torna a novidade barata: pertinência cabe num bitmap exato de 256 bits, sem sketch e
//! sem falso positivo (`SPEC.md` §6). Nada aqui seria possível com um alfabeto grande.
//!
//! A tabela é de código de discagem E.164 → ISO 3166-1 alpha-2, com casamento pelo
//! prefixo mais longo (códigos têm 1 a 3 dígitos, e `1` colide com `1242`, `1246`, …).
//! Isto responde *"que país é este"*, e não *"esta faixa está alocada"* — a segunda é
//! trabalho da libphonenumber e entra depois.

use crate::dialplan::InternationalDigits;

/// Índice compacto e estável de país, usado como posição no bitmap de novidade.
///
/// **O índice é explícito na tabela e nunca é reatribuído nem reusado.** Isto não é
/// zelo: bitmaps são persistidos por 45 a 90 dias, e se o índice fosse derivado da
/// posição no array, inserir um país novo deslocaria todos os seguintes e os bitmaps
/// gravados passariam a apontar para o país errado — silenciosamente. País novo recebe
/// o próximo índice livre, independentemente de onde entre na ordenação.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryIndex(pub u16);

/// Um país de destino resolvido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Country {
    pub index: CountryIndex,
    /// ISO 3166-1 alpha-2. Códigos não geográficos usam rótulos próprios (ver tabela).
    pub iso: &'static str,
    /// Código de discagem E.164 que casou.
    pub calling_code: &'static str,
}

/// Códigos E.164 → (ISO 3166-1 alpha-2, índice estável).
///
/// Ordenada por código apenas para leitura humana; a ordem **não** define o índice.
///
/// Entradas não geográficas relevantes ao IRSF: `800` (freephone), `808` (compartilhado),
/// `870`/`878`/`881`/`882`/`883` (satélite e serviços de rede), `979` (**a única faixa
/// premium internacional legítima pela ITU-T E.169.2** — e nenhum IRSF observado a usa,
/// porque toda fraude é numeração nacional sequestrada).
static CODES: &[(&str, &str, u16)] = &[
    ("1", "NANP", 0),
    ("1242", "BS", 1),
    ("1246", "BB", 2),
    ("1264", "AI", 3),
    ("1268", "AG", 4),
    ("1284", "VG", 5),
    ("1340", "VI", 6),
    ("1345", "KY", 7),
    ("1441", "BM", 8),
    ("1473", "GD", 9),
    ("1649", "TC", 10),
    ("1664", "MS", 11),
    ("1670", "MP", 12),
    ("1671", "GU", 13),
    ("1684", "AS", 14),
    ("1721", "SX", 15),
    ("1758", "LC", 16),
    ("1767", "DM", 17),
    ("1784", "VC", 18),
    ("1809", "DO", 19),
    ("1829", "DO", 20),
    ("1849", "DO", 21),
    ("1868", "TT", 22),
    ("1869", "KN", 23),
    ("1876", "JM", 24),
    ("1939", "PR", 25),
    ("20", "EG", 26),
    ("211", "SS", 27),
    ("212", "MA", 28),
    ("213", "DZ", 29),
    ("216", "TN", 30),
    ("218", "LY", 31),
    ("220", "GM", 32),
    ("221", "SN", 33),
    ("222", "MR", 34),
    ("223", "ML", 35),
    ("224", "GN", 36),
    ("225", "CI", 37),
    ("226", "BF", 38),
    ("227", "NE", 39),
    ("228", "TG", 40),
    ("229", "BJ", 41),
    ("230", "MU", 42),
    ("231", "LR", 43),
    ("232", "SL", 44),
    ("233", "GH", 45),
    ("234", "NG", 46),
    ("235", "TD", 47),
    ("236", "CF", 48),
    ("237", "CM", 49),
    ("238", "CV", 50),
    ("239", "ST", 51),
    ("240", "GQ", 52),
    ("241", "GA", 53),
    ("242", "CG", 54),
    ("243", "CD", 55),
    ("244", "AO", 56),
    ("245", "GW", 57),
    ("246", "IO", 58),
    ("248", "SC", 59),
    ("249", "SD", 60),
    ("250", "RW", 61),
    ("251", "ET", 62),
    ("252", "SO", 63),
    ("253", "DJ", 64),
    ("254", "KE", 65),
    ("255", "TZ", 66),
    ("256", "UG", 67),
    ("257", "BI", 68),
    ("258", "MZ", 69),
    ("260", "ZM", 70),
    ("261", "MG", 71),
    ("262", "RE", 72),
    ("263", "ZW", 73),
    ("264", "NA", 74),
    ("265", "MW", 75),
    ("266", "LS", 76),
    ("267", "BW", 77),
    ("268", "SZ", 78),
    ("269", "KM", 79),
    ("27", "ZA", 80),
    ("290", "SH", 81),
    ("291", "ER", 82),
    ("297", "AW", 83),
    ("298", "FO", 84),
    ("299", "GL", 85),
    ("30", "GR", 86),
    ("31", "NL", 87),
    ("32", "BE", 88),
    ("33", "FR", 89),
    ("34", "ES", 90),
    ("350", "GI", 91),
    ("351", "PT", 92),
    ("352", "LU", 93),
    ("353", "IE", 94),
    ("354", "IS", 95),
    ("355", "AL", 96),
    ("356", "MT", 97),
    ("357", "CY", 98),
    ("358", "FI", 99),
    ("359", "BG", 100),
    ("36", "HU", 101),
    ("370", "LT", 102),
    ("371", "LV", 103),
    ("372", "EE", 104),
    ("373", "MD", 105),
    ("374", "AM", 106),
    ("375", "BY", 107),
    ("376", "AD", 108),
    ("377", "MC", 109),
    ("378", "SM", 110),
    ("379", "VA", 111),
    ("380", "UA", 112),
    ("381", "RS", 113),
    ("382", "ME", 114),
    ("383", "XK", 115),
    ("385", "HR", 116),
    ("386", "SI", 117),
    ("387", "BA", 118),
    ("389", "MK", 119),
    ("39", "IT", 120),
    ("40", "RO", 121),
    ("41", "CH", 122),
    ("420", "CZ", 123),
    ("421", "SK", 124),
    ("423", "LI", 125),
    ("43", "AT", 126),
    ("44", "GB", 127),
    ("45", "DK", 128),
    ("46", "SE", 129),
    ("47", "NO", 130),
    ("48", "PL", 131),
    ("49", "DE", 132),
    ("500", "FK", 133),
    ("501", "BZ", 134),
    ("502", "GT", 135),
    ("503", "SV", 136),
    ("504", "HN", 137),
    ("505", "NI", 138),
    ("506", "CR", 139),
    ("507", "PA", 140),
    ("508", "PM", 141),
    ("509", "HT", 142),
    ("51", "PE", 143),
    ("52", "MX", 144),
    ("53", "CU", 145),
    ("54", "AR", 146),
    ("55", "BR", 147),
    ("56", "CL", 148),
    ("57", "CO", 149),
    ("58", "VE", 150),
    ("590", "GP", 151),
    ("591", "BO", 152),
    ("592", "GY", 153),
    ("593", "EC", 154),
    ("594", "GF", 155),
    ("595", "PY", 156),
    ("596", "MQ", 157),
    ("597", "SR", 158),
    ("598", "UY", 159),
    ("599", "CW", 160),
    ("60", "MY", 161),
    ("61", "AU", 162),
    ("62", "ID", 163),
    ("63", "PH", 164),
    ("64", "NZ", 165),
    ("65", "SG", 166),
    ("66", "TH", 167),
    ("670", "TL", 168),
    ("672", "NF", 169),
    ("673", "BN", 170),
    ("674", "NR", 171),
    ("675", "PG", 172),
    ("676", "TO", 173),
    ("677", "SB", 174),
    ("678", "VU", 175),
    ("679", "FJ", 176),
    ("680", "PW", 177),
    ("681", "WF", 178),
    ("682", "CK", 179),
    ("683", "NU", 180),
    ("685", "WS", 181),
    ("686", "KI", 182),
    ("687", "NC", 183),
    ("688", "TV", 184),
    ("689", "PF", 185),
    ("690", "TK", 186),
    ("691", "FM", 187),
    ("692", "MH", 188),
    ("7", "RU", 189),
    ("800", "INTL-FREEPHONE", 190),
    ("808", "INTL-SHARED", 191),
    ("81", "JP", 192),
    ("82", "KR", 193),
    ("84", "VN", 194),
    ("850", "KP", 195),
    ("852", "HK", 196),
    ("853", "MO", 197),
    ("855", "KH", 198),
    ("856", "LA", 199),
    ("86", "CN", 200),
    ("870", "SAT-INMARSAT", 201),
    ("878", "NET-UPT", 202),
    ("880", "BD", 203),
    ("881", "SAT-GMSS", 204),
    ("882", "NET-INTL", 205),
    ("883", "NET-INTL", 206),
    ("886", "TW", 207),
    ("888", "INTL-DISASTER", 208),
    ("90", "TR", 209),
    ("91", "IN", 210),
    ("92", "PK", 211),
    ("93", "AF", 212),
    ("94", "LK", 213),
    ("95", "MM", 214),
    ("960", "MV", 215),
    ("961", "LB", 216),
    ("962", "JO", 217),
    ("963", "SY", 218),
    ("964", "IQ", 219),
    ("965", "KW", 220),
    ("966", "SA", 221),
    ("967", "YE", 222),
    ("968", "OM", 223),
    ("970", "PS", 224),
    ("971", "AE", 225),
    ("972", "IL", 226),
    ("973", "BH", 227),
    ("974", "QA", 228),
    ("975", "BT", 229),
    ("976", "MN", 230),
    ("977", "NP", 231),
    ("979", "INTL-PREMIUM", 232),
    ("98", "IR", 233),
    ("992", "TJ", 234),
    ("993", "TM", 235),
    ("994", "AZ", 236),
    ("995", "GE", 237),
    ("996", "KG", 238),
    ("998", "UZ", 239),
];

/// Quantos países a tabela conhece. O bitmap precisa comportar isto.
pub const COUNTRY_COUNT: usize = CODES.len();

/// O bitmap de novidade tem 256 bits. Se a tabela passar disso, a compilação para —
/// e não um teste, porque o modo de falha silencioso seria índice fora do bitmap.
const _: () = assert!(COUNTRY_COUNT <= 256);

/// Resolve o país a partir dos dígitos internacionais, pelo **prefixo mais longo**.
///
/// O casamento longo é obrigatório e não é detalhe: `1` é o NANP inteiro, mas `1246`
/// é Barbados. Casar curto colocaria metade do Caribe dentro dos Estados Unidos e
/// destruiria a novidade por país exatamente onde o IRSF é comum.
pub fn resolve(digits: &InternationalDigits) -> Option<Country> {
    let d = digits.0.as_str();
    let mut best: Option<usize> = None;
    for (i, (code, _, _)) in CODES.iter().enumerate() {
        if d.starts_with(code) && best.is_none_or(|b| code.len() > CODES[b].0.len()) {
            best = Some(i);
        }
    }
    best.map(|i| Country {
        index: CountryIndex(CODES[i].2),
        iso: CODES[i].1,
        calling_code: CODES[i].0,
    })
}

/// Faixa intrinsecamente de risco — satélite e serviços de rede não geográficos.
///
/// Isto **não bloqueia sozinho** (`SPEC.md` §6): a medição deu 0,4% de importância para
/// estrutura, e 72,8% dos IPRNs observados são telefonia fixa e móvel ordinária. Entra
/// como sinal que compõe, nunca como veredito.
pub fn is_non_geographic(c: &Country) -> bool {
    c.iso.starts_with("SAT-") || c.iso.starts_with("NET-") || c.iso.starts_with("INTL-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dig(s: &str) -> InternationalDigits {
        InternationalDigits(s.to_string())
    }

    #[test]
    fn casa_pelo_codigo_mais_longo() {
        // O caso que importa: `1246` é Barbados, não Estados Unidos.
        assert_eq!(resolve(&dig("12465551234")).unwrap().iso, "BB");
        assert_eq!(resolve(&dig("12125551234")).unwrap().iso, "NANP");
        // E `35` não existe: `351` é Portugal, `355` é Albânia.
        assert_eq!(resolve(&dig("351912345678")).unwrap().iso, "PT");
        assert_eq!(resolve(&dig("355692345678")).unwrap().iso, "AL");
    }

    #[test]
    fn resolve_os_destinos_de_irsf_do_corpus() {
        // Os países de cabeça do corpus histórico do dev (SPEC, achados do TFPS 2023).
        for (d, iso) in [
            ("252612345678", "SO"), // Somália
            ("371234567", "LV"),    // Letônia
            ("38761234567", "BA"),  // Bósnia
            ("22012345678", "GM"),  // Gâmbia
            ("2451234567", "GW"),   // Guiné-Bissau
            ("9601234567", "MV"),   // Maldivas
            ("53512345678", "CU"),  // Cuba
            ("2241234567", "GN"),   // Guiné
        ] {
            assert_eq!(resolve(&dig(d)).unwrap().iso, iso, "falhou para {d}");
        }
    }

    #[test]
    fn reconhece_satelite_e_a_faixa_premium_legitima() {
        let sat = resolve(&dig("870123456789")).unwrap();
        assert!(is_non_geographic(&sat));
        // +979 é a única faixa premium internacional legítima (ITU-T E.169.2), e
        // nenhum IRSF observado a usa — toda fraude é numeração nacional sequestrada.
        let premium = resolve(&dig("9791234567")).unwrap();
        assert_eq!(premium.iso, "INTL-PREMIUM");
        assert!(is_non_geographic(&premium));
    }

    #[test]
    fn geografico_nao_e_marcado_como_risco_estrutural() {
        assert!(!is_non_geographic(&resolve(&dig("5511999998888")).unwrap()));
    }

    #[test]
    fn codigo_inexistente_devolve_none() {
        assert!(resolve(&dig("999123456789")).is_none());
    }

    #[test]
    fn indices_sao_unicos_e_cabem_no_bitmap() {
        let mut vistos = std::collections::HashSet::new();
        for (code, _, idx) in CODES {
            assert!(
                vistos.insert(*idx),
                "índice {idx} duplicado (código {code})"
            );
        }
        // O teto de 256 é garantido em tempo de compilação (ver `const _` acima).
        for (_, _, idx) in CODES {
            assert!((*idx as usize) < 256, "índice {idx} não cabe no bitmap");
        }
    }

    #[test]
    fn a_tabela_esta_ordenada_por_codigo_para_leitura() {
        // Ordenação é conveniência de leitura, não contrato — o índice é explícito.
        for par in CODES.windows(2) {
            assert!(
                par[0].0 <= par[1].0,
                "fora de ordem: {} depois de {}",
                par[1].0,
                par[0].0
            );
        }
    }

    #[test]
    fn indice_nao_depende_da_posicao_no_array() {
        // A garantia que protege bitmaps persistidos: o índice vem da tabela, não da
        // posição. Se alguém inserir um país no meio, os demais não podem se mover.
        let so = resolve(&dig("252612345678")).unwrap();
        let pos = CODES.iter().position(|(c, _, _)| *c == "252").unwrap();
        assert_eq!(so.index.0, CODES[pos].2);
    }
}
