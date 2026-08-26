// Programa XDP do TFPS — descarta tráfego SIP de origens já condenadas.
//
// Este é o programa que faz o lixo **sumir do sngrep**, e a razão é a ordem no kernel:
// o XDP roda em `netif_receive_skb_internal`, antes de `__netif_receive_skb_core`
// entregar o pacote aos taps `ptype_all` — que é onde o libpcap (logo o sngrep, o
// tcpdump e o tshark) engata. Pacote descartado aqui nunca chega ao tap.
//
// É por isso que o `nftables` não serviria: o drop dele acontece em netfilter, depois
// do tap, e a captura continuaria poluída.
//
// Escrito em C e não em Rust porque só o lado kernel precisa de LLVM/clang, e mantê-lo
// em C dispensa o `bpf-linker` na máquina de desenvolvimento. O lado userspace é Rust
// com `aya`, que é Rust puro.
//
// Compilar (no alvo, com o vmlinux.h gerado do BTF):
//   clang -O2 -g -target bpf -c tfps_xdp.c -o tfps_xdp.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP_ 17

// Teto de origens bloqueadas simultaneamente. `LRU_HASH` despeja a entrada menos usada
// quando enche, o que dá um limite de memória rígido — o programa nunca cresce sem fim,
// ao contrário do que o lado userspace fazia antes desta revisão.
#define MAX_BLOCKED 65536

// Origens condenadas: IPv4 em ordem de rede -> instante de expiração em ns monotônicos.
// Valor 0 significa "sem expiração".
//
// A expiração existe porque bloqueio errado precisa se desfazer sozinho: ninguém vai
// estar acordado às 3h da manhã para desbloquear um cliente legítimo.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED);
    __type(key, __u32);
    __type(value, __u64);
} blocked SEC(".maps");

// Portas SIP observadas. Só o tráfego para/de estas portas é descartado.
//
// **Limitar o raio de dano é deliberado**: um IP atrás de CGNAT pode hospedar um scanner
// e um usuário legítimo ao mesmo tempo. Descartar tudo daquele endereço derrubaria o SSH
// e a web de quem não fez nada. Aqui o dano fica contido ao SIP.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} sip_ports SEC(".maps");

// Contadores: [0] descartados, [1] observados, [2] expirados.
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
        return XDP_PASS; // IPv6 e o resto passam — ver a limitação registrada no README

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP_)
        return XDP_PASS;

    // O IHL vem em palavras de 32 bits e é controlado pelo remetente; o verifier exige
    // que o limite seja checado depois de calculá-lo.
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
        // Expirou: remove e deixa passar. O desbloqueio acontece sozinho, sem varredura
        // em segundo plano e sem ninguém precisar intervir.
        bpf_map_delete_elem(&blocked, &src);
        bump(C_EXPIRED);
        return XDP_PASS;
    }

    bump(C_DROPPED);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
