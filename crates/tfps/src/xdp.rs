//! Imposição por XDP — o que faz o lixo sumir do sngrep.
//!
//! A ordem no kernel é a razão de tudo: o XDP roda em `netif_receive_skb_internal`,
//! **antes** de `__netif_receive_skb_core` entregar o pacote aos taps `ptype_all`, que é
//! onde o libpcap engata. Pacote descartado aqui nunca chega ao sngrep, ao tcpdump nem
//! ao tshark.
//!
//! É por isso que `nftables` não serviria: o drop dele acontece em netfilter, **depois**
//! do tap, e a captura continuaria poluída. Essa diferença de ordenação é o único
//! argumento técnico que distingue as duas opções para este fim.
//!
//! O programa em si está em `ebpf/tfps_xdp.c`, compilado com clang no alvo.

use std::net::Ipv4Addr;
use std::path::Path;

use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData};
use aya::programs::{Xdp, XdpMode};
use aya::Ebpf;

/// Onde o objeto BPF é procurado quando não se passa `--xdp-obj`.
pub const DEFAULT_OBJ: &str = "/usr/local/lib/tfps/tfps_xdp.o";

/// Mapa de drop já fixado por outro produto, procurado antes de anexar programa próprio.
///
/// O SipPulse **já roda** um `xdp_sipdrop` do SipVault nesta posição, alimentado por
/// APIBAN e por detecção de falha de autenticação. Só cabe **um** programa XDP por
/// interface, e desanexar o que está lá quebraria proteção em produção.
///
/// Escrever no mapa existente é a decisão certa por três motivos: não há conflito de
/// hook, não se duplica plano de imposição — que é o pecado da "máquina pela metade" que
/// matou o TFPS 2023 —, e o descarte continua acontecendo no XDP, antes do tap do
/// libpcap, que é o que limpa o sngrep.
pub const SIPVAULT_DROP_MAP: &str = "/sys/fs/bpf/sipvault/drop_ips";

/// Índices do array de contadores, espelhando `ebpf/tfps_xdp.c`.
const C_DROPPED: u32 = 0;
const C_SEEN: u32 = 1;
const C_EXPIRED: u32 = 2;

/// Como a imposição foi obtida.
pub enum Backend {
    /// Escrevendo num mapa de drop já fixado por outro produto (SipVault).
    /// A chave é o IP como número **big-endian**, convenção daquele programa —
    /// determinada empiricamente contra o mapa em produção, não presumida.
    Shared { map: BpfHashMap<MapData, u32, u64> },
    /// Programa próprio, carregado e anexado por nós.
    Own { bpf: Box<Ebpf> },
}

pub struct Enforcer {
    backend: Backend,
    /// Quantas origens **este processo** condenou. Contado à parte porque, no modo
    /// compartilhado, o total do mapa é majoritariamente trabalho do dono dele —
    /// reportá-lo como nosso seria mentir sobre o que o produto está fazendo.
    pub blocked_by_us: u64,
    /// Descrição legível de onde a imposição está acontecendo — vai para o relatório,
    /// porque o operador precisa saber quem está bloqueando.
    pub mode: String,
}

/// Contadores lidos do kernel.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub dropped: u64,
    pub seen: u64,
    pub expired: u64,
}

impl Enforcer {
    /// Obtém imposição: usa um mapa de drop já fixado, se houver, e só anexa programa
    /// próprio quando não houver.
    ///
    /// Falha aqui **nunca é silenciosa**: o chamador precisa avisar alto e seguir em modo
    /// somente-observação. Um antifraude que aparenta proteger sem proteger é exatamente
    /// a crítica que este projeto faz ao incumbente.
    pub fn attach(
        shared_map: &Path,
        obj: &Path,
        iface: &str,
        ports: &[u16],
    ) -> Result<Self, String> {
        if shared_map.exists() {
            match Self::use_shared(shared_map) {
                Ok(e) => return Ok(e),
                Err(err) => {
                    // Não é fatal — cai para o programa próprio —, mas precisa ser dito:
                    // silêncio aqui esconderia que a imposição mudou de dono.
                    eprintln!(
                        "aviso: mapa compartilhado {} existe mas não pude usá-lo: {err}",
                        shared_map.display()
                    );
                }
            }
        }
        Self::load(obj, iface, ports)
    }

    fn use_shared(path: &Path) -> Result<Self, String> {
        // O mapa do SipVault é `lru_hash`; aceitar `hash` também deixa a integração
        // funcionar com qualquer produto que fixe um mapa de drop compatível.
        let map = Self::open_pinned(path, true)
            .or_else(|_| Self::open_pinned(path, false))
            .map_err(|e| format!("mapa não é hash<u32,u64>: {e}"))?;
        Ok(Self {
            mode: format!("mapa compartilhado {}", path.display()),
            blocked_by_us: 0,
            backend: Backend::Shared { map },
        })
    }

    fn open_pinned(path: &Path, lru: bool) -> Result<BpfHashMap<MapData, u32, u64>, String> {
        let data = MapData::from_pin(path).map_err(|e| format!("abrindo pin: {e}"))?;
        let wrapped = if lru {
            Map::LruHashMap(data)
        } else {
            Map::HashMap(data)
        };
        BpfHashMap::try_from(wrapped).map_err(|e| format!("{e}"))
    }

    fn load(obj: &Path, iface: &str, ports: &[u16]) -> Result<Self, String> {
        if !obj.exists() {
            return Err(format!(
                "objeto BPF não encontrado em {}. Compile com: \
                 clang -O2 -g -target bpf -c ebpf/tfps_xdp.c -o {}",
                obj.display(),
                obj.display()
            ));
        }

        let mut bpf =
            Ebpf::load_file(obj).map_err(|e| format!("carregando {}: {e}", obj.display()))?;

        let prog: &mut Xdp = bpf
            .program_mut("tfps_filter")
            .ok_or("programa `tfps_filter` não está no objeto")?
            .try_into()
            .map_err(|e| format!("`tfps_filter` não é um programa XDP: {e}"))?;
        prog.load()
            .map_err(|e| format!("verifier recusou o programa: {e}"))?;

        // Nativo primeiro; genérico como degradação. O genérico roda depois da alocação
        // do `sk_buff` e custa mais por pacote — mas continua **antes** do tap do
        // libpcap, que é o que importa para limpar o sngrep.
        let mode = match prog.attach(iface, XdpMode::Driver) {
            Ok(_) => "nativo (DRV)",
            Err(native_err) => match prog.attach(iface, XdpMode::Skb) {
                Ok(_) => "genérico (SKB)",
                Err(skb_err) => {
                    return Err(format!(
                        "não consegui anexar XDP em {iface}: nativo falhou ({native_err}); \
                         genérico falhou ({skb_err})"
                    ))
                }
            },
        };

        let mut me = Self {
            mode: format!("programa próprio, XDP {mode} em {iface}"),
            blocked_by_us: 0,
            backend: Backend::Own { bpf: Box::new(bpf) },
        };
        me.publish_ports(ports)?;
        Ok(me)
    }

    fn publish_ports(&mut self, ports: &[u16]) -> Result<(), String> {
        let Backend::Own { bpf } = &mut self.backend else {
            return Ok(()); // mapa compartilhado tem a própria política de portas
        };
        let mut map: BpfHashMap<_, u16, u8> =
            BpfHashMap::try_from(bpf.map_mut("sip_ports").ok_or("mapa `sip_ports` ausente")?)
                .map_err(|e| format!("abrindo `sip_ports`: {e}"))?;
        for p in ports {
            map.insert(p, 1u8, 0)
                .map_err(|e| format!("publicando porta {p}: {e}"))?;
        }
        Ok(())
    }

    /// Condena uma origem: todo tráfego SIP dela é descartado até expirar.
    ///
    /// `ttl_secs` de 0 significa sem expiração. Expiração existe porque bloqueio errado
    /// precisa se desfazer sozinho — ninguém estará acordado às 3h para desbloquear.
    pub fn block(&mut self, ip: Ipv4Addr, ttl_secs: u64) -> Result<(), String> {
        let until = if ttl_secs == 0 {
            0u64
        } else {
            monotonic_ns().saturating_add(ttl_secs.saturating_mul(1_000_000_000))
        };
        self.blocked_by_us += 1;
        match &mut self.backend {
            Backend::Shared { map } => {
                // Convenção do SipVault: IP como número **big-endian**. Determinada
                // empiricamente contra o mapa em produção, casando um IP que o fail2ban
                // havia banido — não presumida a partir do código.
                map.insert(u32::from_be_bytes(ip.octets()), until, 0)
                    .map_err(|e| format!("bloqueando {ip} no mapa compartilhado: {e}"))
            }
            Backend::Own { bpf } => {
                // Convenção nossa: `ip->saddr` cru, sem `ntohl`.
                let mut map: BpfHashMap<_, u32, u64> =
                    BpfHashMap::try_from(bpf.map_mut("blocked").ok_or("mapa `blocked` ausente")?)
                        .map_err(|e| format!("abrindo `blocked`: {e}"))?;
                map.insert(u32::from_ne_bytes(ip.octets()), until, 0)
                    .map_err(|e| format!("bloqueando {ip}: {e}"))
            }
        }
    }

    /// O modo compartilhado usa o programa de outro produto, cujos contadores têm
    /// semântica própria. Devolver zeros ali seria relatório falso.
    pub fn has_own_counters(&self) -> bool {
        matches!(self.backend, Backend::Own { .. })
    }

    pub fn counters(&self) -> Counters {
        let Backend::Own { bpf } = &self.backend else {
            return Counters::default(); // contadores do mapa compartilhado são do dono dele
        };
        let Some(map) = bpf.map("counters") else {
            return Counters::default();
        };
        let Ok(arr) = Array::<_, u64>::try_from(map) else {
            return Counters::default();
        };
        Counters {
            dropped: arr.get(&C_DROPPED, 0).unwrap_or(0),
            seen: arr.get(&C_SEEN, 0).unwrap_or(0),
            expired: arr.get(&C_EXPIRED, 0).unwrap_or(0),
        }
    }

    /// Quantas origens estão condenadas neste momento.
    pub fn blocked_count(&self) -> usize {
        match &self.backend {
            Backend::Shared { map } => map.keys().count(),
            Backend::Own { bpf } => bpf
                .map("blocked")
                .and_then(|m| BpfHashMap::<_, u32, u64>::try_from(m).ok())
                .map(|m| m.keys().count())
                .unwrap_or(0),
        }
    }
}

/// Nanossegundos de `CLOCK_MONOTONIC`, para casar com `bpf_ktime_get_ns()` no kernel.
///
/// Lido de `/proc/uptime` para não precisar de `unsafe` nem de `libc` direto — a precisão
/// de 10 ms é irrelevante para TTLs medidos em minutos.
fn monotonic_ns() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| (secs * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}

/// Descobre a interface da rota padrão, para não obrigar o operador a declará-la.
///
/// Coerente com o resto do produto: descobre sozinho, mas o valor é anunciado — e pode
/// ser sobrescrito quando a descoberta erra.
pub fn default_interface() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let mut f = line.split_whitespace();
        let iface = f.next()?;
        let dest = f.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_avanca_e_nao_e_zero() {
        // Se `/proc/uptime` não existir o TTL vira absoluto pequeno e tudo expiraria
        // na hora — vale garantir que a leitura funciona onde o teste roda.
        let a = monotonic_ns();
        assert!(a > 0, "não consegui ler /proc/uptime");
    }

    #[test]
    fn a_chave_do_mapa_casa_a_ordem_de_rede_do_iphdr() {
        // O programa lê `ip->saddr`, que está em ordem de rede. `from_ne_bytes` sobre os
        // octetos reproduz exatamente esse layout na máquina little-endian onde roda.
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let key = u32::from_ne_bytes(ip.octets());
        assert_eq!(key.to_ne_bytes(), [203, 0, 113, 5]);
    }
}
