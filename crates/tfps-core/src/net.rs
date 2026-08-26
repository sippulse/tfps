//! IPv4/UDP parsing — the minimum needed to reach the SIP payload.
//!
//! Capture delivers raw IP packets (`AF_PACKET`/`SOCK_DGRAM`, or an XDP payload later).
//! Nothing here builds state or validates checksums: the goal is to find the SIP datagram
//! and the source address — the **peer**, the only non-forgeable identity from the
//! system's observation point (`CONTEXT.md`, entry "Peer").

use std::net::Ipv4Addr;

const IPPROTO_UDP: u8 = 17;
const IPV4_MIN_HEADER: usize = 20;
const UDP_HEADER: usize = 8;

/// A UDP datagram located inside an IPv4 packet.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// What a packet was, when it is not usable IPv4/UDP.
///
/// The distinction matters: this project defines itself by **not failing silently**, and
/// ignoring an entire traffic family without counting it would be the same failure it
/// criticises in `fail2ban`. IPv6 and SIP over TCP are real blind spots and must be
/// visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotUdp {
    Ipv6,
    Tcp,
    /// A fragment with no L4 header — only the first fragment carries ports.
    LaterFragment,
    Other,
}

/// Source and destination ports of a TCP segment over IPv4, if any.
///
/// This exists so the blind-spot warning can be **specific**: counting all TCP on the wire
/// would include SSH and HTTP, and an alarm that fires because of the administrator's own
/// session is noise, not signal.
pub fn tcp_ports(pkt: &[u8]) -> Option<(u16, u16)> {
    if pkt.len() < IPV4_MIN_HEADER || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER || pkt.len() < ihl + 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
        u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
    ))
}

/// Classifies non-IPv4/UDP traffic so blind spots can be counted.
pub fn classify_other(pkt: &[u8]) -> NotUdp {
    if pkt.is_empty() {
        return NotUdp::Other;
    }
    match pkt[0] >> 4 {
        6 => NotUdp::Ipv6,
        4 if pkt.len() >= IPV4_MIN_HEADER => {
            let frag = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
            if frag != 0 {
                NotUdp::LaterFragment
            } else if pkt[9] == 6 {
                NotUdp::Tcp
            } else {
                NotUdp::Other
            }
        }
        _ => NotUdp::Other,
    }
}

/// Locates a UDP datagram inside an IPv4 packet.
///
/// Returns `None` for anything that is not well-formed IPv4/UDP — including non-first
/// fragments. **A non-initial fragment has no L4 header**, one of the limitations recorded
/// in the eBPF research: the observer sees loose fragments and only the first carries
/// ports.
pub fn parse_ipv4_udp(pkt: &[u8]) -> Option<UdpDatagram<'_>> {
    if pkt.len() < IPV4_MIN_HEADER {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER || pkt.len() < ihl {
        return None;
    }
    if pkt[9] != IPPROTO_UDP {
        return None;
    }

    // Fragmentation: only the zero-offset fragment carries the UDP header.
    let frag_offset = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
    if frag_offset != 0 {
        return None;
    }

    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    // Some paths deliver a buffer larger than the declared `total_len` (Ethernet
    // padding). Trusting the smaller of the two avoids reading junk as if it were SIP.
    let end = total_len.clamp(ihl, pkt.len());

    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    let udp = pkt.get(ihl..end)?;
    if udp.len() < UDP_HEADER {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_end = udp_len.clamp(UDP_HEADER, udp.len());

    Some(UdpDatagram {
        src,
        dst,
        src_port,
        dst_port,
        payload: &udp[UDP_HEADER..payload_end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal IPv4/UDP packet with the given payload.
    fn packet(payload: &[u8], proto: u8, frag_offset: u16) -> Vec<u8> {
        let total = (IPV4_MIN_HEADER + UDP_HEADER + payload.len()) as u16;
        let mut p = vec![0u8; IPV4_MIN_HEADER];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&total.to_be_bytes());
        let frag = frag_offset.to_be_bytes();
        p[6] = frag[0] & 0x1f;
        p[7] = frag[1];
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 0, 0, 5]);
        p[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let udp_len = (UDP_HEADER + payload.len()) as u16;
        p.extend_from_slice(&5060u16.to_be_bytes());
        p.extend_from_slice(&5060u16.to_be_bytes());
        p.extend_from_slice(&udp_len.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn extracts_payload_and_source() {
        let pkt = packet(b"INVITE sip:1@x SIP/2.0\r\n", IPPROTO_UDP, 0);
        let d = parse_ipv4_udp(&pkt).unwrap();
        assert_eq!(d.src, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(d.dst_port, 5060);
        assert_eq!(d.payload, b"INVITE sip:1@x SIP/2.0\r\n");
    }

    #[test]
    fn ignores_what_is_not_udp() {
        assert!(parse_ipv4_udp(&packet(b"x", 6, 0)).is_none(), "TCP");
    }

    #[test]
    fn ignores_non_initial_fragments() {
        // No L4 header; reading ports here would mean reading mid-payload.
        assert!(parse_ipv4_udp(&packet(b"xxxxxxxx", IPPROTO_UDP, 185)).is_none());
    }

    #[test]
    fn ethernet_padding_does_not_become_payload() {
        let mut pkt = packet(b"INVITE", IPPROTO_UDP, 0);
        pkt.extend_from_slice(&[0u8; 20]); // frame padding
        let d = parse_ipv4_udp(&pkt).unwrap();
        assert_eq!(
            d.payload, b"INVITE",
            "padding must not leak into the payload"
        );
    }

    #[test]
    fn classifies_blind_spots_instead_of_ignoring_them() {
        // IPv6: first nibble is 6.
        assert_eq!(classify_other(&[0x60, 0, 0, 0]), NotUdp::Ipv6);
        // TCP over IPv4 — the port 5061 case, which operators commonly configure.
        assert_eq!(classify_other(&packet(b"x", 6, 0)), NotUdp::Tcp);
        // Non-initial fragment.
        assert_eq!(
            classify_other(&packet(b"xxxx", IPPROTO_UDP, 185)),
            NotUdp::LaterFragment
        );
    }

    #[test]
    fn reads_tcp_ports_so_the_warning_is_specific() {
        let mut p = packet(b"", 6, 0);
        // The builder puts 5060/5060 right after the IP header; for TCP the port offsets
        // are the same.
        assert_eq!(tcp_ports(&p), Some((5060, 5060)));
        p[9] = IPPROTO_UDP;
        assert_eq!(tcp_ports(&p), None, "UDP is not TCP");
    }

    #[test]
    fn rejects_junk_without_panicking() {
        assert!(parse_ipv4_udp(&[]).is_none());
        assert!(parse_ipv4_udp(&[0x45]).is_none());
        assert!(parse_ipv4_udp(&[0xff; 20]).is_none(), "invalid version");
        // IHL below the legal minimum.
        let mut p = packet(b"x", IPPROTO_UDP, 0);
        p[0] = 0x43;
        assert!(parse_ipv4_udp(&p).is_none());
    }
}
