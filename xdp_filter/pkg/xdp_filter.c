//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // IPv4 address
    __type(value, __u8);
    __uint(max_entries, 1024);    
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked) {
        bpf_printk("Dropped packet from: %x\n", src_ip);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";