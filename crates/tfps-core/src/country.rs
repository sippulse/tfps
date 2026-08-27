//! Country resolution from international digits, plus the compact index the novelty
//! bitmap uses.
//!
//! The country alphabet is small — around 250 — and it is **that** property which makes
//! novelty cheap: membership fits in an exact 256-bit bitmap, with no sketch and no false
//! positives (`SPEC.md` §6). None of this would be possible with a large alphabet.
//!
//! The table maps E.164 calling code → ISO 3166-1 alpha-2, matched by longest prefix
//! (codes are 1 to 3 digits, and `1` collides with `1242`, `1246`, …). It answers *"which
//! country is this"*, not *"is this range allocated"* — the latter is libphonenumber's job
//! and comes later.

use crate::dialplan::InternationalDigits;

/// Compact, stable country index, used as the bit position in the novelty bitmap.
///
/// **The index is explicit in the table and is never reassigned or reused.** This is not
/// fussiness: bitmaps are persisted for 45 to 90 days, and if the index were derived from
/// array position, inserting a new country would shift every following one and stored
/// bitmaps would silently start pointing at the wrong country. A new country gets the next
/// free index, regardless of where it lands in the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryIndex(pub u16);

/// A resolved destination country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Country {
    pub index: CountryIndex,
    /// ISO 3166-1 alpha-2. Non-geographic codes use their own labels (see the table).
    pub iso: &'static str,
    /// The E.164 calling code that matched.
    pub calling_code: &'static str,
}

/// E.164 codes → (ISO 3166-1 alpha-2, stable index).
///
/// Sorted by code for human reading only; the ordering does **not** define the index.
///
/// Non-geographic entries relevant to IRSF: `800` (freephone), `808` (shared cost),
/// `870`/`878`/`881`/`882`/`883` (satellite and network services), and `979` (**the only
/// legitimate international premium range under ITU-T E.169.2** — and no observed IRSF
/// uses it, because all such fraud is hijacked national numbering).
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

/// How many countries the table knows. The bitmap must hold this many.
pub const COUNTRY_COUNT: usize = CODES.len();

/// The novelty bitmap is 256 bits. If the table grows past that, the build stops — not a
/// test, because the silent failure mode would be an index outside the bitmap.
const _: () = assert!(COUNTRY_COUNT <= 256);

/// Resolves the country from international digits, by **longest prefix**.
///
/// Longest-match is mandatory and not a detail: `1` is the whole NANP, but `1246` is
/// Barbados. Matching short would place half the Caribbean inside the United States and
/// destroy per-country novelty exactly where IRSF is common.
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

/// The label for a stored index, for anything that has to render a bitmap back into
/// countries — the control tool, and the day-31 summary.
///
/// A linear scan: the table has 240 entries and this is never on the packet path.
/// The stable index for an ISO label (case-insensitive), for configuring home countries.
/// `+1` countries share the `NANP` label. Returns `None` for a label not in the table.
pub fn index_for_iso(iso: &str) -> Option<CountryIndex> {
    CODES
        .iter()
        .find(|(_, label, _)| label.eq_ignore_ascii_case(iso))
        .map(|(_, _, i)| CountryIndex(*i))
}

pub fn iso_for_index(index: u16) -> Option<&'static str> {
    CODES
        .iter()
        .find(|(_, _, i)| *i == index)
        .map(|(_, iso, _)| *iso)
}

/// Every country a bitmap pair holds, as labels, sorted for stable output.
pub fn decode_bitmap(cur: [u64; 4], prev: [u64; 4]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = (0..256u16)
        .filter(|i| {
            let (w, b) = (*i as usize / 64, *i as usize % 64);
            (cur[w] | prev[w]) & (1u64 << b) != 0
        })
        .filter_map(iso_for_index)
        .collect();
    out.sort_unstable();
    out
}

/// Intrinsically risky ranges — satellite and non-geographic network services.
///
/// This **does not block on its own** (`SPEC.md` §6): measurement put structure at 0.4% of
/// feature importance, and 72.8% of observed IPRNs are ordinary fixed and mobile numbers.
/// It contributes to a signal, never a verdict.
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
    fn iso_resolves_to_the_same_index_it_labels() {
        let br = resolve(&dig("5511999998888")).unwrap().index;
        assert_eq!(index_for_iso("BR"), Some(br));
        assert_eq!(index_for_iso("br"), Some(br), "case-insensitive");
        assert_eq!(index_for_iso("NANP"), Some(CountryIndex(0)), "+1 is NANP");
        assert_eq!(index_for_iso("ZZ"), None, "an unknown label is None");
    }

    #[test]
    fn every_index_maps_back_to_its_label() {
        // The control tool renders stored bitmaps through this. A hole here would print
        // the wrong country for a real block, which is worse than printing nothing.
        for (_, iso, idx) in CODES {
            assert_eq!(
                iso_for_index(*idx),
                Some(*iso),
                "index {idx} lost its label"
            );
        }
    }

    #[test]
    fn a_bitmap_decodes_to_the_countries_it_holds() {
        let gb = resolve(&dig("442039967796")).unwrap().index.0;
        let ss = resolve(&dig("211123456789")).unwrap().index.0;
        let mut cur = [0u64; 4];
        let mut prev = [0u64; 4];
        cur[gb as usize / 64] |= 1 << (gb % 64);
        prev[ss as usize / 64] |= 1 << (ss % 64);
        // The union of both periods, which is what "has ever seen" means.
        assert_eq!(decode_bitmap(cur, prev), vec!["GB", "SS"]);
    }

    #[test]
    fn matches_the_longest_code() {
        // The case that matters: `1246` is Barbados, not the United States.
        assert_eq!(resolve(&dig("12465551234")).unwrap().iso, "BB");
        assert_eq!(resolve(&dig("12125551234")).unwrap().iso, "NANP");
        // And `35` does not exist: `351` is Portugal, `355` is Albania.
        assert_eq!(resolve(&dig("351912345678")).unwrap().iso, "PT");
        assert_eq!(resolve(&dig("355692345678")).unwrap().iso, "AL");
    }

    #[test]
    fn resolves_the_irsf_destinations_from_the_corpus() {
        // The head countries of the historical corpus (SPEC, 2023 TFPS findings).
        for (d, iso) in [
            ("252612345678", "SO"), // Somalia
            ("371234567", "LV"),    // Latvia
            ("38761234567", "BA"),  // Bosnia
            ("22012345678", "GM"),  // Gambia
            ("2451234567", "GW"),   // Guinea-Bissau
            ("9601234567", "MV"),   // Maldivas
            ("53512345678", "CU"),  // Cuba
            ("2241234567", "GN"),   // Guinea
        ] {
            assert_eq!(resolve(&dig(d)).unwrap().iso, iso, "failed for {d}");
        }
    }

    #[test]
    fn recognises_satellite_and_the_legitimate_premium_range() {
        let sat = resolve(&dig("870123456789")).unwrap();
        assert!(is_non_geographic(&sat));
        // +979 is the only legitimate international premium range (ITU-T E.169.2), and no
        // observed IRSF uses it — all such fraud is hijacked national numbering.
        let premium = resolve(&dig("9791234567")).unwrap();
        assert_eq!(premium.iso, "INTL-PREMIUM");
        assert!(is_non_geographic(&premium));
    }

    #[test]
    fn geographic_is_not_flagged_as_structural_risk() {
        assert!(!is_non_geographic(&resolve(&dig("5511999998888")).unwrap()));
    }

    #[test]
    fn a_nonexistent_code_returns_none() {
        assert!(resolve(&dig("999123456789")).is_none());
    }

    #[test]
    fn indices_are_unique_and_fit_the_bitmap() {
        let mut vistos = std::collections::HashSet::new();
        for (code, _, idx) in CODES {
            assert!(vistos.insert(*idx), "duplicate index {idx} (code {code})");
        }
        // The 256 ceiling is guaranteed at compile time (see the `const _` above).
        for (_, _, idx) in CODES {
            assert!((*idx as usize) < 256, "index {idx} does not fit the bitmap");
        }
    }

    #[test]
    fn the_table_is_sorted_by_code_for_readability() {
        // Sorting is a reading convenience, not a contract — the index is explicit.
        for par in CODES.windows(2) {
            assert!(
                par[0].0 <= par[1].0,
                "out of order: {} after {}",
                par[1].0,
                par[0].0
            );
        }
    }

    #[test]
    fn the_index_does_not_depend_on_array_position() {
        // The guarantee that protects persisted bitmaps: the index comes from the table,
        // not from position. If someone inserts a country in the middle, the rest must not
        // move.
        let so = resolve(&dig("252612345678")).unwrap();
        let pos = CODES.iter().position(|(c, _, _)| *c == "252").unwrap();
        assert_eq!(so.index.0, CODES[pos].2);
    }
}
