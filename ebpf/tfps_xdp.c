// TFPS XDP program — drops SIP traffic from sources already condemned.
//
// This is the program that makes the garbage **vanish from sngrep**, and the reason is
// the ordering inside the kernel: XDP runs in `netif_receive_skb_internal`, before
// `__netif_receive_skb_core` hands the packet to the `ptype_all` taps — which is where
// libpcap (hence sngrep, tcpdump and tshark) hooks in. A packet dropped here never
// reaches the tap.
//
// That is why `nftables` would not do: its drop happens in netfilter, after the tap, and
// the capture would stay polluted.
//
// Written in C rather than Rust because only the kernel side needs LLVM/clang, and
// keeping it in C means no `bpf-linker` on the development machine. The userspace side is
// Rust with `aya`, which is pure Rust.
//
// Build (on the target, with vmlinux.h generated from BTF):
//   clang -O2 -g -target bpf -c tfps_xdp.c -o tfps_xdp.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP_ 17

// Ceiling on simultaneously blocked sources. `LRU_HASH` evicts the least recently used
// entry when it fills up, which gives a hard memory bound — the program never grows
// without limit, unlike what the userspace side did before this revision.
#define MAX_BLOCKED 65536

// Condemned sources: IPv4 in network order -> expiry instant in monotonic ns.
// A value of 0 means "never expires".
//
// Expiry exists because a wrong block has to undo itself: nobody will be awake at 3am to
// unblock a legitimate customer.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED);
    __type(key, __u32);
    __type(value, __u64);
} blocked SEC(".maps");

// Watched SIP ports. Only traffic to/from these ports is dropped.
//
// **Limiting the blast radius is deliberate**: an IP behind CGNAT can host a scanner and
// a legitimate user at the same time. Dropping everything from that address would take
// down SSH and the web for people who did nothing. Here the damage stays confined to SIP.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} sip_ports SEC(".maps");

// Counters: [0] dropped, [1] seen, [2] expired.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define C_DROPPED 0
#define C_SEEN    1
#define C_EXPIRED 2

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        __sync_fetch_and_add(c, 1);
}

static __always_inline int is_sip_port(__u16 port)
{
    __u8 *v = bpf_map_lookup_elem(&sip_ports, &port);
    return v != 0;
}

SEC("xdp")
int tfps_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // IPv6 and the rest pass — see the limitation recorded in the README

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP_)
        return XDP_PASS;

    // IHL comes in 32-bit words and is controlled by the sender; the verifier demands the
    // bound be checked after computing it.
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;
    if ((void *)ip + ihl + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ihl;
    __u16 dport = bpf_ntohs(udp->dest);
    __u16 sport = bpf_ntohs(udp->source);
    if (!is_sip_port(dport) && !is_sip_port(sport))
        return XDP_PASS;

    bump(C_SEEN);

    __u32 src = ip->saddr;
    __u64 *until = bpf_map_lookup_elem(&blocked, &src);
    if (!until)
        return XDP_PASS;

    if (*until != 0 && bpf_ktime_get_ns() > *until) {
        // Expired: remove it and let it through. Unblocking happens on its own, with no
        // background sweep and nobody having to intervene.
        bpf_map_delete_elem(&blocked, &src);
        bump(C_EXPIRED);
        return XDP_PASS;
    }

    bump(C_DROPPED);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
