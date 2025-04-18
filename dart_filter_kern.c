#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DART_PROTO_NUM 254
#define ICMP_PROTO_NUM 1
#define ETH_P_IP 0x0800

struct dart_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u8 dart_version;
    __u8 dart_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB ring buffer
} events SEC(".maps");


SEC("xdp")
int dart_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // bpf_printk 输出的内容会被写入到 /sys/kernel/debug/tracing/trace_pipe 中
    // 需要在用户态使用 sudo cat /sys/kernel/debug/tracing/trace_pipe 来查看
    bpf_printk("XDP packet: data=%p, data_end=%p\n", data, data_end); 
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        bpf_printk("XDP packet: ethhdr is not valid\n");
        return XDP_PASS;
    }
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        bpf_printk("XDP packet: not IP protocol\n");
        return XDP_PASS;
    }
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end){
        bpf_printk("XDP packet: iphdr is not valid\n");
        return XDP_PASS;
    }
    
    if (iph->protocol != DART_PROTO_NUM){
        bpf_printk("XDP packet: not DART protocol\n");
        return XDP_PASS;
    }
    
    __u32 ip_hdr_len = iph->ihl * 4;
    void *dart_ptr = (void *)iph + ip_hdr_len;
    if (dart_ptr + 4 > data_end){
        bpf_printk("XDP packet: dart_ptr is not valid\n");
        return XDP_PASS;
    }
    
    __u8 version = *((__u8 *)dart_ptr);
    __u8 proto = *((__u8 *)(dart_ptr + 1));
    __u8 dst_len = *((__u8 *)(dart_ptr + 2));
    __u8 src_len = *((__u8 *)(dart_ptr + 3));
    
    bpf_printk("DART packet: src_ip=%u.%u.%u.%u, dst_ip=%u.%u.%u.%u, version=%u, proto=%u\n",
               (iph->saddr & 0xFF), (iph->saddr >> 8) & 0xFF, (iph->saddr >> 16) & 0xFF, (iph->saddr >> 24) & 0xFF,
               (iph->daddr & 0xFF), (iph->daddr >> 8) & 0xFF, (iph->daddr >> 16) & 0xFF, (iph->daddr >> 24) & 0xFF,
               version, proto);

    if ((dart_ptr + 4 + dst_len + src_len) > data_end){
        bpf_printk("XDP packet: dart_ptr + 4 + dst_len + src_len is not valid\n");
        return XDP_PASS;
    }


    if (proto == ICMP_PROTO_NUM) {
        bpf_printk("DART packet: ICMP protocol\n");
        struct dart_event ev = {
            .src_ip = iph->saddr,
            .dst_ip = iph->daddr,
            .dart_version = version,
            .dart_proto = proto,
        };
        // bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

        return XDP_DROP;
    }

    return XDP_PASS;
}
