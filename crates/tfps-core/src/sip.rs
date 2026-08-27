//! Just enough SIP parsing for TFPS — and nothing beyond it.
//!
//! This module is **not a SIP stack**. It extracts from a datagram the fields the system
//! needs to decide and to forge a response, and ignores everything else. The boundary is in
//! `SPEC.md` §1: *it does not speak SIP beyond forging responses*.
//!
//! Parsing borrows from the input buffer (zero-copy). The decision path runs per
//! international INVITE, so nothing here allocates.

/// SIP method. Only the ones the system observes; everything else is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Invite,
    Register,
    Bye,
    Cancel,
    Ack,
    Options,
    Other,
}

impl Method {
    fn from_token(tok: &str) -> Self {
        // SIP methods are case-sensitive and uppercase (RFC 3261 §7.1).
        match tok {
            "INVITE" => Self::Invite,
            "REGISTER" => Self::Register,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "ACK" => Self::Ack,
            "OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }
}

/// A SIP request, borrowing from the original buffer.
///
/// The `via`, `from`, `to`, `call_id` and `cseq` fields are kept **raw** because forging a
/// response reuses them literally (RFC 3261 §17.1.3, and `SPEC.md` §8). Not normalising
/// here is deliberate: rewriting what you are about to copy back only creates room for
/// error.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: Method,
    /// Raw Request-URI, exactly as it arrived on the request line.
    pub request_uri: &'a str,
    /// User part of the Request-URI — the dialled number, still **not canonical**.
    pub request_user: Option<&'a str>,
    pub via: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub call_id: Option<&'a str>,
    pub cseq: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub p_asserted_identity: Option<&'a str>,
    /// The credential presented. Its **presence** is the brute-force signal: a `REGISTER`
    /// carrying `Authorization` is a password attempt, whereas the `401` preceding it is
    /// just the normal challenge.
    pub authorization: Option<&'a str>,
    /// A line continuation occurred (folded header). Rare and legal; flagged because this
    /// parser does not join them, so a folded value comes out truncated.
    pub folded: bool,
}

impl<'a> Request<'a> {
    /// User part of `From` — the A-number, an **unverified assertion** by the sender (see
    /// `CONTEXT.md`, entry "A-number").
    pub fn from_user(&self) -> Option<&'a str> {
        self.from.and_then(uri_user)
    }

    /// The `From` tag, needed to match a forged response.
    pub fn from_tag(&self) -> Option<&'a str> {
        self.from.and_then(|v| param(v, "tag"))
    }

    /// The topmost `Via` `branch` — the transaction matcher of RFC 3261 §17.1.3.
    pub fn via_branch(&self) -> Option<&'a str> {
        self.via.and_then(|v| param(v, "branch"))
    }

    /// Did this request carry a credential?
    ///
    /// **This is the whole authentication signal.** A request without one that receives a
    /// `401` is the normal digest handshake; a request *with* one that receives a `401` is
    /// a rejected password.
    pub fn is_authenticated_attempt(&self) -> bool {
        self.authorization.is_some()
    }
}

/// Extracts the user part from a SIP URI embedded in a header value.
///
/// Accepts the forms that show up in practice: `sip:user@host`, `<sip:user@host>`,
/// `"Name" <sip:user@host>;tag=x`, and `tel:+55...`.
fn uri_user(value: &str) -> Option<&str> {
    let start = value
        .find("sip:")
        .or_else(|| value.find("sips:"))
        .or_else(|| value.find("tel:"))?;
    let after_scheme = &value[start..];
    let colon = after_scheme.find(':')? + 1;
    let rest = &after_scheme[colon..];

    // The user part ends at `@`; with no `@` (the `tel:` case) it ends at a delimiter.
    let end = rest.find('@').unwrap_or_else(|| {
        rest.find(|c: char| c == '>' || c == ';' || c == '?' || c.is_whitespace())
            .unwrap_or(rest.len())
    });
    let user = &rest[..end];
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

/// Extracts a `;name=value` parameter from a header value.
fn param<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    for part in value.split(';').skip(1) {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            let end = v
                .find(|c: char| c == ',' || c == '>' || c.is_whitespace())
                .unwrap_or(v.len());
            return Some(&v[..end]);
        }
    }
    None
}

/// Matches a header name, accepting the compact form from RFC 3261 §20.
fn header_is(name: &str, long: &str, compact: Option<&str>) -> bool {
    name.eq_ignore_ascii_case(long) || compact.is_some_and(|c| name.eq_ignore_ascii_case(c))
}

/// A SIP response.
///
/// It carries `via`, `call_id` and `cseq` because a response has to be **matched back to
/// the request that provoked it**: a `401` only means "the credential was wrong" if the
/// request it answers actually carried one. Without that pairing, the challenge every
/// legitimate registration receives is indistinguishable from a failed password.
#[derive(Debug, Clone, Copy)]
pub struct Response<'a> {
    pub status: u16,
    pub call_id: Option<&'a str>,
    /// Topmost `Via`, copied verbatim from the request by the responder.
    pub via: Option<&'a str>,
    pub cseq: Option<&'a str>,
}

impl<'a> Response<'a> {
    /// The `branch` of the topmost `Via` — the transaction identifier of RFC 3261 §17.1.3.
    pub fn via_branch(&self) -> Option<&'a str> {
        self.via.and_then(|v| param(v, "branch"))
    }

    /// Is this a **digest challenge** — `401` from a registrar, `407` from a proxy?
    ///
    /// Named in full because `CONTEXT.md` reserves plain "challenge" for a verdict that
    /// diverts a suspicious call to voice verification. Two different things; one word
    /// between them would be a silent bug.
    pub fn is_digest_challenge(&self) -> bool {
        self.status == 401 || self.status == 407
    }

    /// Did the request succeed? Any `2xx`.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Identifies the transaction a request and its responses share.
///
/// The `branch` of the topmost `Via` is the exact identifier (RFC 3261 §17.1.3) and the
/// responder copies it verbatim, so it matches without ambiguity. `Call-ID` + `CSeq` is the
/// fallback for the pre-3261 stacks that still appear in the wild.
///
/// **`CSeq` is part of the key on purpose**: a client retrying a password keeps one
/// `Call-ID` and increments `CSeq`, so keying on `Call-ID` alone would collapse an entire
/// guessing run into a single countable failure.
pub fn transaction_key(
    branch: Option<&str>,
    call_id: Option<&str>,
    cseq: Option<&str>,
) -> Option<String> {
    // Both halves are attacker-controlled and a datagram can carry tens of kilobytes of
    // either, so the key is capped: a real RFC 3261 branch is around forty characters, and
    // an unbounded key would turn the pending-transaction ceiling into a memory multiplier.
    const MAX_KEY_LEN: usize = 128;
    let clip = |s: &str| {
        let mut end = MAX_KEY_LEN.min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    };
    if let Some(b) = branch {
        if !b.is_empty() {
            return Some(clip(b));
        }
    }
    let c = call_id?;
    Some(clip(&format!("{c}|{}", cseq.unwrap_or(""))))
}

/// A SIP message is either a request or a response. The distinction matters for
/// observability: counting a response as "not SIP" would make an operator conclude they
/// are capturing the wrong interface — and this whole project defines itself by not
/// failing silently.
#[derive(Debug, Clone)]
pub enum Message<'a> {
    Request(Box<Request<'a>>),
    Response(Response<'a>),
    /// The CRLF keepalive of RFC 5626 §4.4.1 — a client behind NAT sends `\r\n\r\n` and
    /// the server replies `\r\n`, purely to hold the NAT pinhole open.
    ///
    /// Its own category out of reporting honesty: on a 5060 port with residential clients
    /// **this is most of the packets**, and counting it as "not SIP" would make an operator
    /// conclude they are capturing the wrong interface.
    Keepalive,
}

/// Parses a SIP datagram, request or response.
pub fn parse(buf: &[u8]) -> Option<Message<'_>> {
    // Keepalive first: the most frequent case and the cheapest to recognise.
    if buf.len() <= 4 && !buf.is_empty() && buf.iter().all(|b| matches!(b, b'\r' | b'\n')) {
        return Some(Message::Keepalive);
    }
    let text = core::str::from_utf8(buf).ok()?;
    if text.starts_with("SIP/") {
        return parse_response(text).map(Message::Response);
    }
    parse_request(buf).map(|r| Message::Request(Box::new(r)))
}

fn parse_response(text: &str) -> Option<Response<'_>> {
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let status_line = lines.next()?;
    let mut parts = status_line.split(' ');
    let _version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;

    let (mut call_id, mut via, mut cseq) = (None, None, None);
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        // Only the topmost Via: it is the one the responder copied from the request.
        if via.is_none() && header_is(name, "Via", Some("v")) {
            via = Some(value);
        } else if header_is(name, "Call-ID", Some("i")) {
            call_id = Some(value);
        } else if header_is(name, "CSeq", None) {
            cseq = Some(value);
        }
    }
    Some(Response {
        status,
        call_id,
        via,
        cseq,
    })
}

/// Parses a SIP datagram.
///
/// Returns `None` when the buffer is not UTF-8 or does not start with a plausible request
/// line. **That is not a system error and never a reason to block** — `SPEC.md` §4:
/// whatever cannot be interpreted falls out of scope and passes.
pub fn parse_request(buf: &[u8]) -> Option<Request<'_>> {
    // SIP headers are ASCII in practice. A non-UTF-8 payload is junk or is not SIP; the
    // handling is the same either way: not this system's business.
    let text = core::str::from_utf8(buf).ok()?;

    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next()?;

    let mut parts = request_line.split(' ');
    let method = Method::from_token(parts.next()?);
    let request_uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("SIP/") {
        return None;
    }

    let mut req = Request {
        method,
        request_uri,
        request_user: uri_user(request_uri),
        via: None,
        from: None,
        to: None,
        call_id: None,
        cseq: None,
        user_agent: None,
        p_asserted_identity: None,
        authorization: None,
        folded: false,
    };

    for line in lines {
        if line.is_empty() {
            break; // end of headers; the body (SDP) is irrelevant
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            req.folded = true;
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();

        // Only the topmost Via matters: it is what the response reuses.
        if req.via.is_none() && header_is(name, "Via", Some("v")) {
            req.via = Some(value);
        } else if header_is(name, "From", Some("f")) {
            req.from = Some(value);
        } else if header_is(name, "To", Some("t")) {
            req.to = Some(value);
        } else if header_is(name, "Call-ID", Some("i")) {
            req.call_id = Some(value);
        } else if header_is(name, "CSeq", None) {
            req.cseq = Some(value);
        } else if header_is(name, "User-Agent", None) {
            req.user_agent = Some(value);
        } else if header_is(name, "P-Asserted-Identity", None) {
            req.p_asserted_identity = Some(value);
        } else if header_is(name, "Authorization", None)
            || header_is(name, "Proxy-Authorization", None)
        {
            req.authorization = Some(value);
        }
    }

    Some(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = concat!(
        "INVITE sip:9011252612345678@pbx.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK776asdhds;rport\r\n",
        "Max-Forwards: 70\r\n",
        "From: \"Ext 200\" <sip:200@pbx.example.com>;tag=1928301774\r\n",
        "To: <sip:9011252612345678@pbx.example.com>\r\n",
        "Call-ID: a84b4c76e66710@pc33.example.com\r\n",
        "CSeq: 314159 INVITE\r\n",
        "User-Agent: Grandstream GXP2140 1.0.9.14\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 131\r\n",
        "\r\n",
        "v=0\r\no=- 53655765 2353687637 IN IP4 10.0.0.5\r\n",
    );

    #[test]
    fn extracts_the_fields_of_an_invite() {
        let r = parse_request(INVITE.as_bytes()).expect("must parse");
        assert_eq!(r.method, Method::Invite);
        assert_eq!(r.request_user, Some("9011252612345678"));
        assert_eq!(r.from_user(), Some("200"));
        assert_eq!(r.from_tag(), Some("1928301774"));
        assert_eq!(r.via_branch(), Some("z9hG4bK776asdhds"));
        assert_eq!(r.call_id, Some("a84b4c76e66710@pc33.example.com"));
        assert_eq!(r.cseq, Some("314159 INVITE"));
        assert_eq!(r.user_agent, Some("Grandstream GXP2140 1.0.9.14"));
        assert!(!r.folded);
    }

    #[test]
    fn distinguishes_register_with_and_without_a_credential() {
        // Without `Authorization`: the first REGISTER, which only triggers the challenge.
        let without = "REGISTER sip:pbx SIP/2.0\r\nFrom: <sip:1@pbx>\r\n\r\n";
        assert!(parse_request(without.as_bytes())
            .unwrap()
            .authorization
            .is_none());
        // With `Authorization`: a password attempt — the thing that gets counted.
        let with = "REGISTER sip:pbx SIP/2.0\r\n\
                   From: <sip:1@pbx>\r\n\
                   Authorization: Digest username=\"1001\", response=\"abc\"\r\n\r\n";
        let r = parse_request(with.as_bytes()).unwrap();
        assert!(r.authorization.is_some());
        assert_eq!(r.method, Method::Register);
    }

    #[test]
    fn accepts_the_compact_form_and_bare_lf() {
        let msg = "INVITE sip:5511999998888@example.com SIP/2.0\n\
                   v: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKabc\n\
                   f: <sip:1000@example.com>;tag=xyz\n\
                   t: <sip:5511999998888@example.com>\n\
                   i: call-123\n\
                   CSeq: 1 INVITE\n\
                   \n";
        let r = parse_request(msg.as_bytes()).expect("must parse");
        assert_eq!(r.from_user(), Some("1000"));
        assert_eq!(r.via_branch(), Some("z9hG4bKabc"));
        assert_eq!(r.call_id, Some("call-123"));
    }

    #[test]
    fn only_the_topmost_via_is_kept() {
        let msg = "INVITE sip:1@e.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP top;branch=FIRST\r\n\
                   Via: SIP/2.0/UDP bottom;branch=SECOND\r\n\
                   \r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert_eq!(r.via_branch(), Some("FIRST"));
    }

    #[test]
    fn a_folded_header_is_flagged() {
        let msg = "INVITE sip:1@e.com SIP/2.0\r\n\
                   From: <sip:200@e.com>\r\n\
                   \t;tag=continuacao\r\n\
                   \r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert!(r.folded, "a line continuation must be flagged");
    }

    #[test]
    fn tel_uri_without_an_at_sign() {
        let msg = "INVITE tel:+5511999998888 SIP/2.0\r\n\r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert_eq!(r.request_user, Some("+5511999998888"));
    }

    #[test]
    fn a_response_is_not_mistaken_for_junk() {
        // The case that showed up in the first real-traffic run: 8 of 10 packets on port
        // 5060 were responses, and the counter said "not SIP".
        let msg = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\r\n\
                   Call-ID: abc-123\r\n\
                   CSeq: 1 INVITE\r\n\r\n";
        match parse(msg.as_bytes()).expect("must parse") {
            Message::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.call_id, Some("abc-123"));
            }
            other => panic!("expected a response, got {other:?}"),
        }
        // And a request is still a request.
        assert!(matches!(
            parse(INVITE.as_bytes()),
            Some(Message::Request(_))
        ));
        // Junk is still junk.
        assert!(parse(b"not sip at all").is_none());
    }

    #[test]
    fn a_nat_keepalive_is_not_junk() {
        // Seen on the first deployment: 6 of 8 packets on a real 5060 were 2-byte
        // payloads. They are softphones behind NAT holding the pinhole open.
        for ka in [&b"\r\n"[..], &b"\r\n\r\n"[..], &b"\n"[..]] {
            assert!(
                matches!(parse(ka), Some(Message::Keepalive)),
                "should recognise a keepalive from {ka:?}"
            );
        }
        // An empty payload is not a keepalive; it is a packet with no content.
        assert!(parse(b"").is_none());
        // And a 4-byte payload that is not CRLF is still junk.
        assert!(parse(b"abcd").is_none());
    }

    #[test]
    fn an_error_response_is_recognised_too() {
        for (raw, code) in [
            ("SIP/2.0 403 Forbidden\r\n\r\n", 403u16),
            ("SIP/2.0 486 Busy Here\r\n\r\n", 486),
        ] {
            match parse(raw.as_bytes()).unwrap() {
                Message::Response(r) => assert_eq!(r.status, code),
                _ => panic!("expected a response"),
            }
        }
    }

    #[test]
    fn non_sip_is_rejected_without_panicking() {
        assert!(parse_request(b"binary junk \xff\xfe").is_none());
        assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"INVITE\r\n").is_none());
    }

    #[test]
    fn an_unknown_method_is_not_an_invite() {
        let msg = "SUBSCRIBE sip:1@e.com SIP/2.0\r\n\r\n";
        assert_eq!(parse_request(msg.as_bytes()).unwrap().method, Method::Other);
    }
}
