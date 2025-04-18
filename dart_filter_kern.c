#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_SIZE 1500

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DART_PROTO_NUM 254
#define ETH_P_IP 0x0800

// 使用RINGBUF替代PERF_EVENT_ARRAY
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB缓冲区
} events SEC(".maps");

struct event {
    u64 ts;
    u32 len;
    u8 pkt[MAX_PACKET_SIZE];
};

SEC("xdp")
int dart_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 仅处理IPv4包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 解析IP头
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 检查DART协议号
    if (iph->protocol != DART_PROTO_NUM)
        return XDP_PASS;

    // 计算包长度
    u32 pkt_len = data_end - data;
    if (pkt_len > MAX_PACKET_SIZE)
        pkt_len = MAX_PACKET_SIZE;

    // 从ringbuf分配内存
    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!ev)
        return XDP_DROP;

    // 填充事件数据
    ev->ts = bpf_ktime_get_ns();
    ev->len = pkt_len;
    bpf_probe_read_kernel(ev->pkt, pkt_len, data);

    // 提交到用户空间
    bpf_ringbuf_submit(ev, 0);

    bpf_printk("DART packet captured and dropped.\n"); 
    return XDP_DROP;
}