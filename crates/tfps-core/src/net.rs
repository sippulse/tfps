//! Parse de IPv4/UDP — o mínimo para chegar ao payload SIP.
//!
//! A captura entrega pacotes IP crus (`AF_PACKET`/`SOCK_DGRAM`, ou o payload de um XDP
//! depois). Nada aqui monta estado nem valida checksum: o objetivo é achar o datagrama
//! SIP e o endereço de origem — que é o **peer**, a única identidade não forjável na
//! posição de observação do sistema (`CONTEXT.md`, verbete Peer).

use std::net::Ipv4Addr;

const IPPROTO_UDP: u8 = 17;
const IPV4_MIN_HEADER: usize = 20;
const UDP_HEADER: usize = 8;

/// Um datagrama UDP localizado dentro de um pacote IPv4.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// O que um pacote era, quando não é IPv4/UDP aproveitável.
///
/// Distinguir importa: o projeto se define por **não falhar em silêncio**, e ignorar uma
/// família inteira de tráfego sem contá-la seria a mesma falha que ele critica no
/// `fail2ban`. IPv6 e SIP sobre TCP são pontos cegos reais e precisam ser visíveis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotUdp {
    Ipv6,
    Tcp,
    /// Fragmento sem cabeçalho L4 — só o primeiro fragmento traz portas.
    LaterFragment,
    Other,
}

/// Portas de origem e destino de um segmento TCP sobre IPv4, se houver.
///
/// Existe para que o aviso de ponto cego seja **específico**: contar todo TCP do fio
/// incluiria SSH e HTTP, e um alarme que dispara por causa da sessão do administrador
/// é ruído, não sinal.
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

/// Classifica o que não é IPv4/UDP, para que os pontos cegos possam ser contados.
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

/// Localiza um datagrama UDP num pacote IPv4.
///
/// Devolve `None` para qualquer coisa que não seja IPv4/UDP bem formado — inclusive
/// fragmentos que não sejam o primeiro. **Fragmento não-inicial não tem cabeçalho L4**,
/// e é uma das limitações registradas na pesquisa de eBPF: o observador vê fragmentos
/// soltos e só o primeiro carrega portas.
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

    // Fragmentação: só o fragmento com offset zero traz o cabeçalho UDP.
    let frag_offset = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
    if frag_offset != 0 {
        return None;
    }

    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    // Alguns caminhos entregam o buffer maior que o `total_len` declarado (padding de
    // Ethernet). Confiar no menor dos dois evita ler lixo como se fosse SIP.
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

    /// Monta um IPv4/UDP mínimo com o payload dado.
    fn packet(payload: &[u8], proto: u8, frag_offset: u16) -> Vec<u8> {
        let total = (IPV4_MIN_HEADER + UDP_HEADER + payload.len()) as u16;
        let mut p = vec![0u8; IPV4_MIN_HEADER];
        p[0] = 0x45; // versão 4, IHL 5
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
    fn extrai_payload_e_origem() {
        let pkt = packet(b"INVITE sip:1@x SIP/2.0\r\n", IPPROTO_UDP, 0);
        let d = parse_ipv4_udp(&pkt).unwrap();
        assert_eq!(d.src, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(d.dst_port, 5060);
        assert_eq!(d.payload, b"INVITE sip:1@x SIP/2.0\r\n");
    }

    #[test]
    fn ignora_o_que_nao_e_udp() {
        assert!(parse_ipv4_udp(&packet(b"x", 6, 0)).is_none(), "TCP");
    }

    #[test]
    fn ignora_fragmento_nao_inicial() {
        // Sem cabeçalho L4; ler portas daqui seria ler o meio de um payload.
        assert!(parse_ipv4_udp(&packet(b"xxxxxxxx", IPPROTO_UDP, 185)).is_none());
    }

    #[test]
    fn padding_de_ethernet_nao_vira_payload() {
        let mut pkt = packet(b"INVITE", IPPROTO_UDP, 0);
        pkt.extend_from_slice(&[0u8; 20]); // padding do quadro
        let d = parse_ipv4_udp(&pkt).unwrap();
        assert_eq!(d.payload, b"INVITE", "o padding não pode entrar no payload");
    }

    #[test]
    fn classifica_os_pontos_cegos_em_vez_de_ignora_los() {
        // IPv6: primeiro nibble 6.
        assert_eq!(classify_other(&[0x60, 0, 0, 0]), NotUdp::Ipv6);
        // TCP sobre IPv4 — o caso da porta 5061, que o operador provavelmente configura.
        assert_eq!(classify_other(&packet(b"x", 6, 0)), NotUdp::Tcp);
        // Fragmento não-inicial.
        assert_eq!(
            classify_other(&packet(b"xxxx", IPPROTO_UDP, 185)),
            NotUdp::LaterFragment
        );
    }

    #[test]
    fn le_portas_de_tcp_para_o_aviso_ser_especifico() {
        let mut p = packet(b"", 6, 0);
        // O construtor põe 5060/5060 logo depois do cabeçalho IP; para TCP a posição
        // das portas é a mesma.
        assert_eq!(tcp_ports(&p), Some((5060, 5060)));
        p[9] = IPPROTO_UDP;
        assert_eq!(tcp_ports(&p), None, "UDP não é TCP");
    }

    #[test]
    fn recusa_lixo_sem_panico() {
        assert!(parse_ipv4_udp(&[]).is_none());
        assert!(parse_ipv4_udp(&[0x45]).is_none());
        assert!(parse_ipv4_udp(&[0xff; 20]).is_none(), "versão inválida");
        // IHL menor que o mínimo legal.
        let mut p = packet(b"x", IPPROTO_UDP, 0);
        p[0] = 0x43;
        assert!(parse_ipv4_udp(&p).is_none());
    }
}
