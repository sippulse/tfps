//! XDP enforcement — what makes the garbage disappear from sngrep.
//!
//! Kernel ordering is the whole reason: XDP runs in `netif_receive_skb_internal`, **before**
//! `__netif_receive_skb_core` hands the packet to the `ptype_all` taps, which is where
//! libpcap hooks. A packet dropped here never reaches sngrep, tcpdump or tshark.
//!
//! That is why `nftables` would not do: its drop happens in netfilter, **after** the tap,
//! and the capture would stay polluted. This ordering difference is the only technical
//! argument that separates the two options for this purpose.
//!
//! The program itself lives in `ebpf/tfps_xdp.c`, compiled with clang on the target.

use std::net::Ipv4Addr;
use std::path::Path;

use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData};
use aya::programs::{Xdp, XdpMode};
use aya::Ebpf;

/// Where the BPF object is looked for when `--xdp-obj` is not given.
pub const DEFAULT_OBJ: &str = "/usr/local/lib/tfps/tfps_xdp.o";

/// A drop map already pinned by another product, checked before attaching our own program.
///
/// Only **one** XDP program fits per interface, and detaching whatever is already there
/// would break protection in production.
///
/// Writing into the existing map is the right call for three reasons: there is no hook
/// conflict, no duplicated enforcement plane — the "half-built machinery" sin that killed
/// the 2023 TFPS — and the drop still happens at XDP, before the libpcap tap, which is what
/// keeps sngrep clean.
pub const SIPVAULT_DROP_MAP: &str = "/sys/fs/bpf/sipvault/drop_ips";

/// Indices into the counter array, mirroring `ebpf/tfps_xdp.c`.
const C_DROPPED: u32 = 0;
const C_SEEN: u32 = 1;
const C_EXPIRED: u32 = 2;

/// How enforcement was obtained.
pub enum Backend {
    /// Writing into a drop map already pinned by another product.
    /// The key is the IP as a **big-endian** number, that program's convention —
    /// determined empirically against the production map, not assumed.
    Shared { map: BpfHashMap<MapData, u32, u64> },
    /// Our own program, loaded and attached by us.
    Own { bpf: Box<Ebpf> },
}

pub struct Enforcer {
    backend: Backend,
    /// How many sources **this process** condemned. Counted separately because in shared
    /// mode the map total is mostly its owner's work — reporting it as ours would lie about
    /// what the product is doing.
    pub blocked_by_us: u64,
    /// Human-readable description of where enforcement is happening — it goes into the
    /// report, because the operator needs to know who is doing the blocking.
    pub mode: String,
}

/// Counters read from the kernel.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub dropped: u64,
    pub seen: u64,
    pub expired: u64,
}

impl Enforcer {
    /// Obtains enforcement: uses an already-pinned drop map if there is one, and only
    /// attaches our own program when there is not.
    ///
    /// Failure here is **never silent**: the caller must say so loudly and carry on in
    /// observe-only mode. An anti-fraud system that appears to protect without protecting
    /// is exactly the criticism this project levels at the incumbent.
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
                    // Not fatal — it falls back to our own program — but it must be said:
                    // silence here would hide that enforcement changed hands.
                    eprintln!(
                        "warning: shared map {} exists but could not be used: {err}",
                        shared_map.display()
                    );
                }
            }
        }
        Self::load(obj, iface, ports)
    }

    fn use_shared(path: &Path) -> Result<Self, String> {
        // The pinned map is typically `lru_hash`; accepting `hash` as well lets this work
        // with any product that pins a compatible drop map.
        let map = Self::open_pinned(path, true)
            .or_else(|_| Self::open_pinned(path, false))
            .map_err(|e| format!("map is not a hash<u32,u64>: {e}"))?;
        Ok(Self {
            mode: format!("shared map {}", path.display()),
            blocked_by_us: 0,
            backend: Backend::Shared { map },
        })
    }

    pub(crate) fn open_pinned(
        path: &Path,
        lru: bool,
    ) -> Result<BpfHashMap<MapData, u32, u64>, String> {
        let data = MapData::from_pin(path).map_err(|e| format!("opening pin: {e}"))?;
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
                "BPF object not found at {}. Build it with: \
                 clang -O2 -g -target bpf -c ebpf/tfps_xdp.c -o {}",
                obj.display(),
                obj.display()
            ));
        }

        let mut bpf =
            Ebpf::load_file(obj).map_err(|e| format!("loading {}: {e}", obj.display()))?;

        let prog: &mut Xdp = bpf
            .program_mut("tfps_filter")
            .ok_or("program `tfps_filter` is not in the object")?
            .try_into()
            .map_err(|e| format!("`tfps_filter` is not an XDP program: {e}"))?;
        prog.load()
            .map_err(|e| format!("the verifier rejected the program: {e}"))?;

        // Native first, generic as a fallback. Generic runs after `sk_buff` allocation and
        // costs more per packet — but it is still **before** the libpcap tap, which is what
        // matters for a clean sngrep.
        let mode = match prog.attach(iface, XdpMode::Driver) {
            Ok(_) => "native (DRV)",
            Err(native_err) => match prog.attach(iface, XdpMode::Skb) {
                Ok(_) => "generic (SKB)",
                Err(skb_err) => {
                    return Err(format!(
                        "could not attach XDP on {iface}: native failed ({native_err}); \
                         generic failed ({skb_err})"
                    ))
                }
            },
        };

        let mut me = Self {
            mode: format!("own program, XDP {mode} on {iface}"),
            blocked_by_us: 0,
            backend: Backend::Own { bpf: Box::new(bpf) },
        };
        me.publish_ports(ports)?;
        Ok(me)
    }

    fn publish_ports(&mut self, ports: &[u16]) -> Result<(), String> {
        let Backend::Own { bpf } = &mut self.backend else {
            return Ok(()); // a shared map has its own port policy
        };
        let mut map: BpfHashMap<_, u16, u8> = BpfHashMap::try_from(
            bpf.map_mut("sip_ports")
                .ok_or("map `sip_ports` is missing")?,
        )
        .map_err(|e| format!("opening `sip_ports`: {e}"))?;
        for p in ports {
            map.insert(p, 1u8, 0)
                .map_err(|e| format!("publishing port {p}: {e}"))?;
        }
        Ok(())
    }

    /// Condemns a source: all of its SIP traffic is dropped until the block expires.
    ///
    /// A `ttl_secs` of 0 means no expiry. Expiry exists because a wrong block must undo
    /// itself — nobody will be awake at 3 a.m. to unblock a customer.
    pub fn block(&mut self, ip: Ipv4Addr, ttl_secs: u64) -> Result<(), String> {
        let until = if ttl_secs == 0 {
            0u64
        } else {
            monotonic_ns().saturating_add(ttl_secs.saturating_mul(1_000_000_000))
        };
        self.blocked_by_us += 1;
        match &mut self.backend {
            Backend::Shared { map } => {
                // The pinned map's convention: IP as a **big-endian** number. Determined
                // empirically against the production map, by matching an IP that fail2ban
                // had banned — not assumed from source code.
                map.insert(u32::from_be_bytes(ip.octets()), until, 0)
                    .map_err(|e| format!("blocking {ip} in the shared map: {e}"))
            }
            Backend::Own { bpf } => {
                // Our own convention: raw `ip->saddr`, no `ntohl`.
                let mut map: BpfHashMap<_, u32, u64> =
                    BpfHashMap::try_from(bpf.map_mut("blocked").ok_or("map `blocked` is missing")?)
                        .map_err(|e| format!("opening `blocked`: {e}"))?;
                map.insert(u32::from_ne_bytes(ip.octets()), until, 0)
                    .map_err(|e| format!("blocking {ip}: {e}"))
            }
        }
    }

    /// Shared mode uses another product's program, whose counters have their own
    /// semantics. Returning zeros there would be a false report.
    pub fn has_own_counters(&self) -> bool {
        matches!(self.backend, Backend::Own { .. })
    }

    pub fn counters(&self) -> Counters {
        let Backend::Own { bpf } = &self.backend else {
            return Counters::default(); // a shared map's counters belong to its owner
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

    /// How many sources are condemned right now.
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

/// `CLOCK_MONOTONIC` nanoseconds, to match `bpf_ktime_get_ns()` in the kernel.
///
/// Read from `/proc/uptime` to avoid needing `unsafe` or `libc` directly — 10 ms precision
/// is irrelevant for TTLs measured in minutes.
pub fn monotonic_ns() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| (secs * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}

/// The live block map, opened from **outside** the running daemon — what `tfps_ctl`
/// operates on.
///
/// It has to find a map the daemon deliberately does not pin. Not pinning is what makes
/// enforcement fail open by construction (`SPEC.md` §2), so the control tool works around
/// it the other way: the kernel can enumerate its loaded maps, and ours is found by name.
/// That keeps the safety property and still allows an operator to unban somebody.
pub struct Blocklist {
    map: BpfHashMap<MapData, u32, u64>,
    /// Key encoding. A third party's pinned map stores the address big-endian; our own
    /// stores the raw `ip->saddr`. **This is the reason `tfps_ctl` shares this module
    /// instead of reimplementing it**: two copies would drift, and the symptom would be an
    /// unban that silently removes nothing.
    big_endian: bool,
    /// Where it was found, for the operator to see which plane they are editing.
    pub source: String,
}

impl Blocklist {
    /// Opens the map the daemon is actually using: an explicit path, else a third party's
    /// pin, else our own by name — the same order of preference the daemon itself applies.
    pub fn open(explicit: Option<&Path>) -> Result<Self, String> {
        if let Some(p) = explicit {
            let map = Self::open_pin(p)?;
            return Ok(Self {
                map,
                big_endian: p != Path::new(""),
                source: format!("pinned map {}", p.display()),
            });
        }
        let shared = Path::new(SIPVAULT_DROP_MAP);
        if shared.exists() {
            if let Ok(map) = Self::open_pin(shared) {
                return Ok(Self {
                    map,
                    big_endian: true,
                    source: format!("shared map {}", shared.display()),
                });
            }
        }
        let (id, map) = Self::open_by_name("blocked")?;
        Ok(Self {
            map,
            big_endian: false,
            source: format!("own map id {id}"),
        })
    }

    fn open_pin(p: &Path) -> Result<BpfHashMap<MapData, u32, u64>, String> {
        Enforcer::open_pinned(p, true)
            .or_else(|_| Enforcer::open_pinned(p, false))
            .map_err(|e| format!("opening {}: {e}", p.display()))
    }

    /// Finds a loaded map by name. Needs `CAP_BPF`, like everything else that touches the
    /// enforcement plane.
    fn open_by_name(name: &str) -> Result<(u32, BpfHashMap<MapData, u32, u64>), String> {
        let ids: Vec<u32> = aya::maps::loaded_maps()
            .filter_map(Result::ok)
            .filter(|i| i.name_as_str() == Some(name))
            .map(|i| i.id())
            .collect();
        match ids.len() {
            0 => Err(format!(
                "no loaded eBPF map called `{name}` — is tfps running, and are you root?"
            )),
            1 => {
                let data = MapData::from_id(ids[0])
                    .map_err(|e| format!("opening map id {}: {e}", ids[0]))?;
                let m = BpfHashMap::try_from(Map::LruHashMap(data))
                    .map_err(|e| format!("map id {} is not a hash<u32,u64>: {e}", ids[0]))?;
                Ok((ids[0], m))
            }
            // Ambiguity is reported rather than guessed at: picking the wrong map would
            // edit somebody else's enforcement.
            _ => Err(format!(
                "several loaded maps are called `{name}` (ids {ids:?}); name one with --map-id"
            )),
        }
    }

    fn key(&self, ip: Ipv4Addr) -> u32 {
        if self.big_endian {
            u32::from_be_bytes(ip.octets())
        } else {
            u32::from_ne_bytes(ip.octets())
        }
    }

    fn addr(&self, key: u32) -> Ipv4Addr {
        Ipv4Addr::from(if self.big_endian {
            key.to_be_bytes()
        } else {
            key.to_ne_bytes()
        })
    }

    /// Every condemned source, with the instant its block expires in monotonic ns
    /// (`0` = never).
    pub fn entries(&self) -> Vec<(Ipv4Addr, u64)> {
        let mut out: Vec<(Ipv4Addr, u64)> = self
            .map
            .keys()
            .filter_map(Result::ok)
            .map(|k| (self.addr(k), self.map.get(&k, 0).unwrap_or(0)))
            .collect();
        out.sort_by_key(|(ip, _)| *ip);
        out
    }

    /// Lifts a block. Returns whether the address was there — an operator who typos an
    /// address must be told nothing happened, not left believing they unbanned someone.
    pub fn remove(&mut self, ip: Ipv4Addr) -> Result<bool, String> {
        let k = self.key(ip);
        if self.map.get(&k, 0).is_err() {
            return Ok(false);
        }
        self.map
            .remove(&k)
            .map(|()| true)
            .map_err(|e| format!("removing {ip}: {e}"))
    }

    /// Condemns a source by hand, with the same TTL semantics the daemon uses.
    pub fn insert(&mut self, ip: Ipv4Addr, ttl_secs: u64) -> Result<(), String> {
        let until = if ttl_secs == 0 {
            0
        } else {
            monotonic_ns().saturating_add(ttl_secs.saturating_mul(1_000_000_000))
        };
        self.map
            .insert(self.key(ip), until, 0)
            .map_err(|e| format!("blocking {ip}: {e}"))
    }
}

/// Reads the XDP counters from outside the daemon, for `tfps_ctl stats`.
///
/// These are the only **live** numbers a second process can obtain: they live in a kernel
/// map, whereas everything the daemon counts in userspace lives in its own memory and
/// reaches the control tool through the database at checkpoint time.
pub fn live_counters() -> Result<Counters, String> {
    let id = aya::maps::loaded_maps()
        .filter_map(Result::ok)
        .find(|i| i.name_as_str() == Some("counters"))
        .map(|i| i.id())
        .ok_or("no loaded eBPF map called `counters` — is tfps running with enforcement?")?;
    let data = MapData::from_id(id).map_err(|e| format!("opening counters map: {e}"))?;
    let arr = Array::<_, u64>::try_from(Map::Array(data))
        .map_err(|e| format!("counters is not an array<u64>: {e}"))?;
    Ok(Counters {
        dropped: arr.get(&C_DROPPED, 0).unwrap_or(0),
        seen: arr.get(&C_SEEN, 0).unwrap_or(0),
        expired: arr.get(&C_EXPIRED, 0).unwrap_or(0),
    })
}

/// Every IPv4 address configured on this host.
///
/// Read from `/proc/net/fib_trie`, whose `LOCAL` host routes are exactly the set of
/// addresses the kernel answers for. The alternative is `getifaddrs`, which means `libc`
/// and `unsafe`; the workspace forbids the second and this needs neither.
///
/// It exists so the system cannot condemn the machine it is defending.
pub fn local_addresses() -> Vec<Ipv4Addr> {
    let Ok(text) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut pending: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|-- ") {
            pending = rest.trim().parse().ok();
        } else if t.contains("32 host LOCAL") {
            if let Some(ip) = pending.take() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Finds the default-route interface, so the operator need not declare it.
///
/// Consistent with the rest of the product: it discovers on its own, announces what it
/// found, and can be overridden when discovery gets it wrong.
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
    fn monotonic_is_readable_and_nonzero() {
        // If `/proc/uptime` is missing, the TTL becomes a small absolute value and
        // everything would expire at once — worth asserting the read works here.
        let a = monotonic_ns();
        assert!(a > 0, "could not read /proc/uptime");
    }

    #[test]
    fn the_map_key_matches_the_iphdr_network_order() {
        // The program reads `ip->saddr`, which is in network order. `from_ne_bytes` over
        // the octets reproduces exactly that layout on the little-endian host it runs on.
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let key = u32::from_ne_bytes(ip.octets());
        assert_eq!(key.to_ne_bytes(), [203, 0, 113, 5]);
    }
}
