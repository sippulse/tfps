//! Perimeter — noise removal by user-agent signature and URI shape.
//!
//! **It does not exist to catch fraud.** It exists to keep garbage out of the behavioural
//! baseline: if scanning feeds a pair's baseline, the model learns that a burst to a
//! strange destination is normal there, and the defence poisons itself (`SPEC.md` §7).
//!
//! It is also the **product's retention hook**: a packet removed here dies at `XDP_DROP`
//! and therefore **never appears in sngrep** — the operator installs it, opens a capture,
//! and the garbage is gone.
//!
//! Calibrated expectations, and they are modest: in the Java-era TFPS the user-agent rule
//! fired 260 times over 19 months, with the list frozen at 16 signatures for a decade. As
//! *detection* that is nearly useless — a competent attacker uses a normal UA. As a
//! **volume filter** it is adequate, because lazy scanners with default UAs are the vast
//! majority of packets.

/// Known tool signatures.
///
/// Inherited from the `dialplan` table (dpid 99997) of the 2023 TFPS, converted from regex
/// to simple matching — every one of them was a start anchor or a literal string, and a
/// prefix matcher avoids a regex dependency on the hot path.
static SIGNATURES: &[(&str, Match)] = &[
    ("sipcli", Match::Prefix),
    ("friendly", Match::Prefix),
    ("VaxUserAgent", Match::Prefix),
    ("VaxSIPUserAgent", Match::Prefix),
    ("sivus", Match::Prefix),
    ("Nsauditor", Match::Prefix),
    ("SipReg", Match::Prefix),
    ("Custom SIP", Match::Prefix),
    ("Nmap NSE", Match::Prefix),
    ("sipscan", Match::Prefix),
    ("sipsorcery", Match::Prefix),
    ("pplsip", Match::Prefix),
    ("SipClient", Match::Prefix),
    ("sipvicious", Match::Prefix),
    ("smap", Match::Exact),
    ("PBX", Match::Exact),
    ("Trixbox", Match::Exact),
    ("opensip", Match::Exact),
];

/// Injection patterns that show up in attack URIs.
///
/// Inherited from rule **R12** of the 2023 `tfps.m4`, which ran seven checks over `$au`,
/// `$ru`, `$rU`, `$fU`, `$fu` and `Contact`. Unlike a user-agent, this has **no innocent
/// explanation**: no phone puts a single quote or `--` in the `From` header. That makes it
/// a higher-confidence signal than the tool list.
static INJECTION: &[&str] = &[
    "'",   // single quote — the classic
    "%27", // percent-encoded single quote
    "--",  // SQL comment
    "\\",  // escape
    "%24", // `$`
    "%60", // backtick
    "==", "?=?",   // seen in the field
    "union", // `UNION SELECT`
    "select", ";", // command separator outside a parameter
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    /// Starts with the signature. Covers `^sipcli`, `^friendly`, and so on.
    Prefix,
    /// Equals the signature exactly. Covers `^PBX$`, `^Trixbox$`, `^opensip$` — anchored
    /// at both ends, because `PBX` as a prefix would match a real PBX's legitimate UA.
    Exact,
}

/// Noise filter, with per-signature counts.
///
/// The counting is not decoration: `SPEC.md` §12 requires reporting patterns that match
/// zero times. A signature that has not fired in three months is rotten, and the operator
/// needs to know — precisely what `fail2ban` never did.
#[derive(Debug, Clone)]
pub struct NoiseFilter {
    hits: Vec<u64>,
    /// Signatures added from a file, with their own counts.
    extra: Vec<(String, Match, u64)>,
    /// Injection patterns added from a file.
    extra_injection: Vec<String>,
    injections: u64,
}

impl Default for NoiseFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseFilter {
    pub fn new() -> Self {
        Self {
            hits: vec![0; SIGNATURES.len()],
            extra: Vec::new(),
            extra_injection: Vec::new(),
            injections: 0,
        }
    }

    /// Does the user-agent match a known scanning-tool signature?
    ///
    /// Case-insensitive comparison: the 2023 TFPS had `^[sS][iI][vV][uU][sS]` written out
    /// by hand for exactly this reason.
    pub fn is_noise(&mut self, user_agent: Option<&str>) -> Option<&'static str> {
        let ua = user_agent?.trim();
        if ua.is_empty() {
            // A missing user-agent is common in legitimate traffic (the Java-era TFPS saw
            // 6,843 INVITEs with no UA). Absence is **not** noise.
            return None;
        }
        for (i, (sig, kind)) in SIGNATURES.iter().enumerate() {
            if matches_sig(ua, sig, *kind) {
                self.hits[i] += 1;
                return Some(sig);
            }
        }
        // File signatures come second: the built-ins keep the report's stable counts.
        for (sig, kind, n) in &mut self.extra {
            if matches_sig(ua, sig, *kind) {
                *n += 1;
                return Some("<file>");
            }
        }
        None
    }

    /// Signatures and how many times each matched, for the report.
    pub fn hits(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        SIGNATURES
            .iter()
            .zip(&self.hits)
            .map(|((sig, _), n)| (*sig, *n))
    }

    /// Adds a user-agent signature coming from a file.
    ///
    /// **It adds, never replaces.** A file that replaced would make an operator who writes
    /// three lines silently lose the 18 built-ins — a silent downgrade, precisely the
    /// failure this project condemns in `fail2ban`.
    ///
    /// Syntax: `text` matches by prefix; `=text` matches exactly (equivalent to `^…$`).
    pub fn add_signature(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return;
        }
        let (kind, sig) = match raw.strip_prefix('=') {
            Some(rest) => (Match::Exact, rest.trim()),
            None => (Match::Prefix, raw),
        };
        if !sig.is_empty() {
            self.extra.push((sig.to_string(), kind, 0));
        }
    }

    /// Adds an injection pattern coming from a file.
    pub fn add_injection(&mut self, raw: &str) {
        let raw = raw.trim();
        if !raw.is_empty() && !raw.starts_with('#') {
            self.extra_injection.push(raw.to_ascii_lowercase());
        }
    }

    /// How many signatures the filter knows in total — built-ins plus file entries.
    pub fn signature_count(&self) -> (usize, usize) {
        (SIGNATURES.len(), self.extra.len())
    }

    pub fn injection_count(&self) -> (usize, usize) {
        (INJECTION.len(), self.extra_injection.len())
    }

    /// Does the URI carry an injection pattern?
    ///
    /// **Only the `user@host` part of each URI is examined**, and that boundary is the
    /// whole safety of this rule. Handing it the raw header value scans the *display name*
    /// too, where an apostrophe or a double hyphen is an ordinary surname: `"O'Brien"`,
    /// `"Smith--Jones"`, `"Select Cars Ltd"` were all condemned as SQL injection by the
    /// previous version — and a perimeter block takes the whole source IP off the network
    /// for an hour, so one call from the wrong customer removed their PBX.
    ///
    /// Nor is it applied to the whole message: `Via`, `User-Agent` and the SDP body contain
    /// legitimate characters that would match by accident.
    pub fn injection_in_uri(&mut self, uris: &[Option<&str>]) -> Option<&'static str> {
        for raw in uris.iter().flatten() {
            let Some(addr) = uri_addr(raw) else {
                continue;
            };
            let lower = addr.to_ascii_lowercase();
            for pat in INJECTION {
                // `;` is legitimate as a SIP URI parameter separator (`;tag=`,
                // `;transport=`), so it only counts inside the **user part**.
                if *pat == ";" {
                    // `;` never survives `uri_addr`, which stops at the first one — so it
                    // is checked against the raw value, restricted to the user part.
                    if user_part(&raw.to_ascii_lowercase()).is_some_and(|u| u.contains(';')) {
                        self.injections += 1;
                        return Some(pat);
                    }
                    continue;
                }
                if lower.contains(pat) {
                    self.injections += 1;
                    return Some(pat);
                }
            }
            for pat in &self.extra_injection {
                if lower.contains(pat.as_str()) {
                    self.injections += 1;
                    return Some("<file>");
                }
            }
        }
        None
    }

    pub fn injections(&self) -> u64 {
        self.injections
    }

    /// Signatures that never matched — the candidates for being rotten.
    pub fn cold_signatures(&self) -> Vec<&'static str> {
        self.hits()
            .filter(|(_, n)| *n == 0)
            .map(|(s, _)| s)
            .collect()
    }
}

/// How many **failed** authentications within the window condemn a source.
///
/// A failure is a request that **carried a credential** and was answered with another
/// `401`/`407`. That pairing is the whole signal, and it is what separates this from
/// counting challenges: every legitimate `REGISTER` receives a `401` with a nonce before
/// being resent with `Authorization`, so counting challenges would block every customer on
/// the network. A phone with the right password is challenged once and then succeeds; one
/// with the wrong password is challenged again, and again.
///
/// Five in ten minutes matches the `maxretry`/`findtime` defaults of the `fail2ban`
/// Asterisk jail — deliberately, since that threshold has a decade of field use behind it.
/// The difference is where the evidence comes from: the wire, immediately, instead of a log
/// file that the softswitch may not even be writing.
pub const AUTH_FAILURES_TO_BLOCK: usize = 5;

/// Window for the failure counter, in seconds.
pub const AUTH_FAILURE_WINDOW_SECS: u32 = 600;

/// Backstop: how many authenticated attempts within a short window condemn a source even
/// when **no response is ever observed**.
///
/// This exists because the failure rule needs to see the softswitch's `401`, and there are
/// real deployments where it never appears: a proxy that drops junk before authenticating
/// it (measured on the reference server: 1 outbound packet in 45 seconds, against hundreds
/// inbound), or a response path over TLS. Without this backstop, a credential-stuffing run
/// against such a server would meet a counter that structurally cannot rise — which is
/// precisely the silent blindness this project exists to avoid.
///
/// It is looser than the failure rule because it cannot tell success from failure, only
/// volume: a legitimate phone sends one per registration cycle, typically every 300 s.
pub const AUTH_ATTEMPTS_TO_BLOCK: usize = 20;

/// Window for the backstop above, in seconds.
///
/// Measured on the reference server: **2 challenges in 45 s** of legitimate traffic, about
/// 2.7/min. Twenty per minute leaves roughly 7× headroom. A large NAT aggregating many
/// phones can still approach it — which the failure rule above does not suffer from, and
/// which is why the block is temporary either way.
pub const AUTH_WINDOW_SECS: u32 = 60;

/// A sliding count of the last `N` events, sized exactly to the threshold it serves.
///
/// If the oldest of `N` timestamps is still inside the window, the threshold has been
/// reached — so nothing older than the last `N` events ever needs storing. Constant memory
/// per source, no allocation, and no background sweep.
#[derive(Debug, Clone)]
pub struct SlidingCount<const N: usize> {
    stamps: [u32; N],
    len: u8,
    next: u8,
}

impl<const N: usize> Default for SlidingCount<N> {
    fn default() -> Self {
        Self {
            stamps: [0; N],
            len: 0,
            next: 0,
        }
    }
}

impl<const N: usize> SlidingCount<N> {
    /// Records an event and reports how many fall inside `span`, and whether that reached
    /// `N`.
    pub fn record(&mut self, now: u32, span: u32) -> (u32, bool) {
        self.stamps[self.next as usize] = now;
        self.next = ((self.next as usize + 1) % N) as u8;
        if (self.len as usize) < N {
            self.len += 1;
        }
        let n = self.count_within(now, span);
        (n, n as usize >= N)
    }

    /// How many events fall inside `span`, without recording one.
    pub fn count_within(&self, now: u32, span: u32) -> u32 {
        self.stamps[..self.len as usize]
            .iter()
            .filter(|s| now.saturating_sub(**s) < span)
            .count() as u32
    }

    /// Forgets everything. Called when a credential is **accepted**: a success means the
    /// earlier rejections were someone typing a password wrong, not an attack.
    pub fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }
}

/// Failed authentications for one source — requests that carried a credential and were
/// rejected.
pub type AuthFailures = SlidingCount<AUTH_FAILURES_TO_BLOCK>;

/// Authenticated attempts for one source, regardless of outcome. The volume backstop.
pub type AuthAttempts = SlidingCount<AUTH_ATTEMPTS_TO_BLOCK>;

fn matches_sig(ua: &str, sig: &str, kind: Match) -> bool {
    match kind {
        Match::Prefix => ua.len() >= sig.len() && ua[..sig.len()].eq_ignore_ascii_case(sig),
        Match::Exact => ua.eq_ignore_ascii_case(sig),
    }
}

/// The `user@host` of a SIP URI, with the display name and the header parameters removed.
///
/// Everything this rule inspects passes through here. The display name is free text an
/// end-user chose; the parameters (`;tag=`, `;transport=tcp`) are structured and
/// legitimate. Injection lands in the user part or the host, and nowhere else.
fn uri_addr(value: &str) -> Option<&str> {
    // Prefer what is inside the angle brackets: a display name is free text and may itself
    // contain something that looks like a URI.
    let scope = match (value.find('<'), value.find('>')) {
        (Some(a), Some(b)) if b > a => &value[a + 1..b],
        _ => value,
    };
    let start = scope
        .find("sip:")
        .map(|i| i + 4)
        .or_else(|| scope.find("sips:").map(|i| i + 5))
        .or_else(|| scope.find("tel:").map(|i| i + 4))?;
    let rest = &scope[start..];
    // Only `>` and `;` end the address. Whitespace does **not**: `sip:1 union select@host`
    // is malformed on purpose and is exactly what this rule is for. The display name needs
    // no terminator, because the scan starts at the scheme and the name precedes it.
    let end = rest.find(['>', ';']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Lower-cased user part of a SIP URI, for the `;` check.
fn user_part(uri: &str) -> Option<&str> {
    let start = uri
        .find("sip:")
        .map(|i| i + 4)
        .or_else(|| uri.find("sips:").map(|i| i + 5))?;
    let rest = &uri[start..];
    let end = rest.find('@')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_the_classic_scanners() {
        let mut f = NoiseFilter::new();
        for ua in [
            "friendly-scanner",
            "sipcli/v1.8",
            "pplsip",
            "sipvicious 0.3.3",
            "Nmap NSE",
            "VaxSIPUserAgent/3.0",
        ] {
            assert!(f.is_noise(Some(ua)).is_some(), "should catch {ua}");
        }
    }

    #[test]
    fn does_not_catch_a_legitimate_user_agent() {
        let mut f = NoiseFilter::new();
        for ua in [
            "Grandstream GXP2140 1.0.9.14",
            "Asterisk PBX 18.9.0",
            "Z 5.5.5 rv2.10.16.6",
            "OpenSIPS (3.2.0 (x86_64/linux))",
            "Cisco-SIPGateway/IOS-12.x",
            "FPBX-2.8.1(1.8.20.0)",
        ] {
            assert!(f.is_noise(Some(ua)).is_none(), "false positive on {ua}");
        }
    }

    #[test]
    fn double_anchoring_avoids_a_false_positive_on_a_real_pbx() {
        let mut f = NoiseFilter::new();
        // `^PBX$` from the 2023 TFPS: only a UA that is exactly "PBX" is a scanner.
        assert!(f.is_noise(Some("PBX")).is_some());
        assert!(f.is_noise(Some("PBX Asterisk 18")).is_none());
        assert!(f.is_noise(Some("opensip")).is_some());
        assert!(f.is_noise(Some("OpenSIPS (3.2.0)")).is_none());
    }

    #[test]
    fn a_missing_user_agent_is_not_noise() {
        // The Java-era TFPS saw 6,843 legitimate INVITEs with no user-agent. Treating
        // absence as noise would discard good traffic — and poison the volume measurement.
        let mut f = NoiseFilter::new();
        assert!(f.is_noise(None).is_none());
        assert!(f.is_noise(Some("")).is_none());
        assert!(f.is_noise(Some("   ")).is_none());
    }

    #[test]
    fn case_does_not_matter() {
        let mut f = NoiseFilter::new();
        assert!(f.is_noise(Some("SIPVICIOUS")).is_some());
        assert!(f.is_noise(Some("SiVuS")).is_some());
    }

    #[test]
    fn catches_injection_in_a_uri() {
        let mut f = NoiseFilter::new();
        for uri in [
            "sip:1001'@pbx.com",
            "sip:admin--@pbx.com",
            "sip:x%27or%271%27=%271@pbx.com",
            "sip:?=?@pbx.com",
            "sip:1 union select@pbx.com",
            "sip:a;drop@pbx.com",
        ] {
            assert!(
                f.injection_in_uri(&[Some(uri)]).is_some(),
                "should catch injection in {uri}"
            );
        }
        assert_eq!(f.injections(), 6);
    }

    #[test]
    fn does_not_catch_a_legitimate_uri() {
        let mut f = NoiseFilter::new();
        for uri in [
            "sip:1001@pbx.example.com",
            "<sip:5511999998888@gw.example.com>;tag=abc123",
            "sip:200@10.0.0.5:5060;transport=udp",
            "\"Ext 200\" <sip:200@pbx.com>;tag=x",
            "sip:+5511999998888@carrier.net;user=phone",
        ] {
            assert!(
                f.injection_in_uri(&[Some(uri)]).is_none(),
                "false positive on {uri}"
            );
        }
    }

    #[test]
    fn a_parameter_semicolon_is_not_injection() {
        // `;tag=`, `;transport=` and `;user=phone` are legitimate and frequent. It only
        // counts when the `;` sits in the user part, before the `@`.
        let mut f = NoiseFilter::new();
        assert!(f
            .injection_in_uri(&[Some("sip:200@pbx.com;transport=tcp")])
            .is_none());
        assert!(f.injection_in_uri(&[Some("sip:20;0@pbx.com")]).is_some());
    }

    #[test]
    fn ordinary_display_names_are_not_sql_injection() {
        // Every one of these was blocked by the first version of this rule, because it was
        // handed the whole header value. A perimeter block condemns the source IP for an
        // hour: one call from a customer called O'Brien removed their PBX from the network.
        let mut f = NoiseFilter::new();
        for from in [
            "\"O'Brien\" <sip:1001@pbx.example.com>;tag=abc",
            "\"Smith--Jones\" <sip:1002@pbx.example.com>;tag=abc",
            "\"Sébastien D'Arcy\" <sip:1003@pbx.example.com>;tag=abc",
            "\"Select Cars Ltd\" <sip:1004@pbx.example.com>;tag=abc",
            "\"Credit Union Desk\" <sip:1005@pbx.example.com>;tag=abc",
            "\"Ext == 200\" <sip:1006@pbx.example.com>;tag=abc",
            // A display name that itself contains a URI must not smuggle the scan back
            // into free text.
            "\"call sip:o'brien now\" <sip:1007@pbx.example.com>;tag=abc",
        ] {
            assert_eq!(
                f.injection_in_uri(&[Some("sip:00442039967796@pbx"), Some(from)]),
                None,
                "display name wrongly condemned: {from}"
            );
        }
    }

    #[test]
    fn an_attack_in_the_user_part_still_fires_after_the_narrowing() {
        // The narrowing must not cost detection: these are the real attack shapes.
        let mut f = NoiseFilter::new();
        for uri in [
            "sip:1001'@pbx.com",
            "sip:admin--@pbx.com",
            "sip:x%27or%271%27=%271@pbx.com",
            "sip:?=?@pbx.com",
            "<sip:1 union select@pbx.com>",
            "sip:a;drop@pbx.com",
        ] {
            assert!(
                f.injection_in_uri(&[Some(uri)]).is_some(),
                "attack no longer detected: {uri}"
            );
        }
    }

    #[test]
    fn a_file_adds_and_never_replaces() {
        let mut f = NoiseFilter::new();
        f.add_signature("MyLocalScanner");
        f.add_signature("=ExactlyThis");
        f.add_signature("# ignored comment");
        f.add_signature("   ");

        // The new one works…
        assert!(f.is_noise(Some("MyLocalScanner/2.0")).is_some());
        assert!(f.is_noise(Some("ExactlyThis")).is_some());
        assert!(
            f.is_noise(Some("ExactlyThis and more")).is_none(),
            "= is double-anchored"
        );
        // …and the built-ins still apply. That is the point: it adds, it does not replace.
        assert!(f.is_noise(Some("friendly-scanner")).is_some());
        assert_eq!(
            f.signature_count(),
            (18, 2),
            "comments and blanks do not count"
        );
    }

    #[test]
    fn file_injection_patterns_also_add() {
        let mut f = NoiseFilter::new();
        f.add_injection("xp_cmdshell");
        assert!(f
            .injection_in_uri(&[Some("sip:a xp_cmdshell b@x")])
            .is_some());
        assert!(
            f.injection_in_uri(&[Some("sip:1001'@x")]).is_some(),
            "the built-in still fires"
        );
        assert_eq!(f.injection_count(), (11, 1));
    }

    #[test]
    fn the_legitimate_digest_challenge_does_not_fire() {
        // A phone registers every 300 s. Even across a full hour it comes nowhere close to
        // the volume backstop.
        let mut a = AuthAttempts::default();
        for cycle in 0..12u32 {
            let (_, blocks) = a.record(cycle * 300, AUTH_WINDOW_SECS);
            assert!(!blocks, "periodic legitimate registration must never block");
        }
    }

    #[test]
    fn the_volume_backstop_fires() {
        let mut a = AuthAttempts::default();
        let mut fired = false;
        for i in 0..AUTH_ATTEMPTS_TO_BLOCK as u32 {
            let (_, b) = a.record(1000 + i, AUTH_WINDOW_SECS); // one per second
            fired = b;
        }
        assert!(fired, "20 attempts in 20 s must block");
    }

    #[test]
    fn five_rejected_credentials_condemn_the_source() {
        // The rule that matters: rejections, not challenges. Five in ten minutes is the
        // fail2ban default, and a run of guesses reaches it easily.
        let mut f = AuthFailures::default();
        let mut fired = false;
        for i in 0..AUTH_FAILURES_TO_BLOCK as u32 {
            let (_, b) = f.record(1000 + i * 30, AUTH_FAILURE_WINDOW_SECS);
            fired = b;
        }
        assert!(fired, "5 rejected credentials in 10 minutes must block");
    }

    #[test]
    fn an_accepted_credential_forgets_the_earlier_rejections() {
        // Someone mistyping a password four times and then getting it right must not be
        // blocked by their next mistake an hour later. Only a *run* of failures is an
        // attack.
        let mut f = AuthFailures::default();
        for i in 0..(AUTH_FAILURES_TO_BLOCK as u32 - 1) {
            assert!(!f.record(1000 + i, AUTH_FAILURE_WINDOW_SECS).1);
        }
        f.clear();
        let (n, blocks) = f.record(1100, AUTH_FAILURE_WINDOW_SECS);
        assert_eq!(n, 1, "the successful login wiped the slate");
        assert!(!blocks);
    }

    #[test]
    fn the_window_slides_instead_of_resetting() {
        let mut a = AuthAttempts::default();
        // 19 attempts, not enough.
        for i in 0..(AUTH_ATTEMPTS_TO_BLOCK as u32 - 1) {
            assert!(!a.record(1000 + i, AUTH_WINDOW_SECS).1);
        }
        // Much later, an isolated attempt must not add up with the old ones.
        let (n, blocks) = a.record(1000 + AUTH_WINDOW_SECS * 3, AUTH_WINDOW_SECS);
        assert_eq!(n, 1);
        assert!(!blocks);
    }

    #[test]
    fn counts_per_signature_and_reports_the_cold_ones() {
        let mut f = NoiseFilter::new();
        f.is_noise(Some("friendly-scanner"));
        f.is_noise(Some("friendly-scanner"));
        f.is_noise(Some("sipcli/v1.8"));

        let hot: Vec<_> = f.hits().filter(|(_, n)| *n > 0).collect();
        assert_eq!(hot.len(), 2);
        assert!(hot.contains(&("friendly", 2)));
        assert!(hot.contains(&("sipcli", 1)));

        // The rest never matched — that is what the report needs to say.
        assert!(f.cold_signatures().contains(&"pplsip"));
        assert!(!f.cold_signatures().contains(&"friendly"));
    }
}
