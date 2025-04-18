// xdp_combined.c
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <ctype.h>
#include <linux/ip.h> // For struct iphdr
#include <linux/icmp.h> // For struct icmphdr
#include <linux/if_packet.h> // For struct sockaddr_ll
#include <linux/if_link.h>   // For XDP_FLAGS_DRV_MODE and other XDP flags
#include "dart_header.h"

#define BPF_FILE "dart_filter_kern.o"
#define PIN_PATH "/sys/fs/bpf/events"
#define MAX_RINGBUF_ENTRIES (1 << 24) // 16 MB ring buffer  
#define MAX_RINGBUF_POLL_TIMEOUT 1000 // 1 second

#define MAX_PACKET_SIZE 1500

static struct bpf_object *obj = NULL;
static struct bpf_link *xdp_link = NULL;
static struct ring_buffer *rb = NULL;

struct event {
    uint64_t ts;
    uint32_t len;
    uint8_t pkt[MAX_PACKET_SIZE];
};

int ifindex; // 接口索引

// 信号处理函数
static void sig_handler(int sig)
{
    printf("\nUnloading XDP program...\n");
    
    // 清理资源
    ring_buffer__free(rb); 
    bpf_link__destroy(xdp_link);
    bpf_object__close(obj);
    
    exit(0);
}

// 事件处理回调
static int handle_event(void *ctx, void *data, size_t size)
{
    struct event *ev = data;
    printf("Packet len: %u\n", ev->len);
    // 打印数据内容
    printf("Data:\n");
    for (size_t i = 0; i < ev->len; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("  ");
                for (size_t j = i - 16; j < i; j++) {
                    printf("%c", isprint(ev->pkt[j]) ? ev->pkt[j] : '.');
                }
            }
            printf("\n%04zx: ", i);
        }
        printf("%02x ", ev->pkt[i]);
    }

    // 打印最后一行的可显示字符
    size_t remainder = ev->len % 16;
    if (remainder > 0) {
        for (size_t i = 0; i < 16 - remainder; i++) {
            printf("   ");
        }
        printf("  ");
        for (size_t i = ev->len - remainder; i < ev->len; i++) {
            printf("%c", isprint(ev->pkt[i]) ? ev->pkt[i] : '.');
        }
    }
    printf("\n");

    // 现在我们已经得到了完整的数据包。
    // 检查是否是ICMP请求
    if (ev->len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) {
        printf("Packet too short for ICMP\n");
        return 0;
    }

    struct ethhdr *eth = (struct ethhdr *)ev->pkt;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    dart_packet_t *dart = (dart_packet_t *)(ip + 1);  //注意DART报头是变长结构，因此只有固定的部分可以直接读取
    struct icmphdr *icmp = (struct icmphdr *)((void *)(dart + 1) + dart->dest_addr_len + dart->src_addr_len);

    // 检查是否是IPv4和ICMP协议
    if (ntohs(eth->h_proto) != ETH_P_IP || ip->protocol != IPPROTO_DART || dart->protocol_number != IPPROTO_ICMP) {
        printf("Not an ICMP packet\n");
        return 0;
    }

    // 检查是否是ICMP请求
    if (icmp->type != ICMP_ECHO) {
        printf("Not an ICMP Echo Request\n");
        return 0;
    }

    printf("ICMP Echo Request detected. Preparing response...\n");

    // 构造ICMP响应
    uint8_t response[MAX_PACKET_SIZE];
    memcpy(response, ev->pkt, ev->len);

    struct ethhdr *resp_eth = (struct ethhdr *)response;
    struct iphdr *resp_ip = (struct iphdr *)(resp_eth + 1);
    dart_packet_t *resp_dart = (dart_packet_t *)(resp_ip + 1);
    struct icmphdr *resp_icmp = (struct icmphdr *)((void *)(resp_dart + 1) + dart->dest_addr_len + dart->src_addr_len);

    // 交换源和目标MAC地址
    memcpy(resp_eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(resp_eth->h_source, eth->h_dest, ETH_ALEN);

    // 交换源和目标IP地址
    resp_ip->saddr = ip->daddr;
    resp_ip->daddr = ip->saddr;

    // 交换源和目标DART地址
    resp_dart->src_addr_len = dart->dest_addr_len;
    resp_dart->dest_addr_len = dart->src_addr_len;

    char *requ_dart_dst = (char *)(dart + 1);
    char *requ_dart_src = requ_dart_dst + dart->dest_addr_len;
    char *resp_dart_dst = (char *)(resp_dart + 1);
    char *resp_dart_src = resp_dart_dst + resp_dart->dest_addr_len;

    memcpy(resp_dart_dst, requ_dart_src, dart->src_addr_len);
    memcpy(resp_dart_src, requ_dart_dst, dart->dest_addr_len);

    // 设置ICMP类型为Echo Reply
    resp_icmp->type = ICMP_ECHOREPLY;

    // 计算完整的ICMP校验和
    resp_icmp->checksum = 0;
    uint16_t *icmp_data = (uint16_t *)resp_icmp;
    size_t icmp_len = ntohs(resp_ip->tot_len) - (resp_ip->ihl * 4) - sizeof(dart_packet_t) - resp_dart->dest_addr_len - resp_dart->src_addr_len;
    uint32_t checksum = 0;

    for (size_t i = 0; i < icmp_len / 2; i++) {
        checksum += icmp_data[i];
    }

    if (icmp_len % 2 == 1) {
        checksum += ((uint8_t *)icmp_data)[icmp_len - 1];
    }

    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    resp_icmp->checksum = ~checksum;

    // 发送响应报文
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return 0;
    }

    struct sockaddr_ll addr = {0};
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, resp_eth->h_dest, ETH_ALEN);


    printf("Packet len: %u\n", ev->len);
    // 打印数据内容
    printf("Data:\n");
    for (size_t i = 0; i < ev->len; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("  ");
                for (size_t j = i - 16; j < i; j++) {
                    printf("%c", isprint(response[j]) ? response[j] : '.');
                }
            }
            printf("\n%04zx: ", i);
        }
        printf("%02x ", response[i]);
    }

    // 打印最后一行的可显示字符
    remainder = ev->len % 16;
    if (remainder > 0) {
        for (size_t i = 0; i < 16 - remainder; i++) {
            printf("   ");
        }
        printf("  ");
        for (size_t i = ev->len - remainder; i < ev->len; i++) {
            printf("%c", isprint(response[i]) ? response[i] : '.');
        }
    }
    printf("\n");


    if (sendto(sock, response, ev->len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Sendto failed");
    } else {
        // printf("ICMP Echo Reply sent\n");
        // Print the serial number of the ICMP packet
        printf("ICMP Serial Number: %u\n", ntohs(icmp->un.echo.sequence));
    }

    close(sock);
    
    return 0;
}

int main(int argc, char **argv)
{
    int map_fd;
    int err;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    
    // 注册信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 加载XDP程序
    // ============================================
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Get ifindex failed: %s\n", strerror(errno));
        return 1;
    }

    // 打开BPF对象文件
    
    obj = bpf_object__open_file(BPF_FILE, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Open BPF object failed\n");
        return 1;
    }

    // 查找并配置events映射
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "Find map 'events' failed\n");
        goto cleanup;
    }
    bpf_map__set_pin_path(map, PIN_PATH);

    // 加载到内核
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "Load BPF object failed: %d\n", err);
        goto cleanup;
    }

    // 附加XDP程序
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "dart_filter");
    if (!prog) {
        fprintf(stderr, "Find XDP program failed\n");
        goto cleanup;
    }

    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Attach XDP failed\n");
        goto cleanup;
    }

    // // 获取程序fd
    // int prog_fd = bpf_program__fd(prog);
    // if (prog_fd < 0) {
    //     fprintf(stderr, "Get program fd failed\n");
    //     goto cleanup;
    // }

    // // 使用bpf_xdp_attach强制Native模式
    // int opts_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE;  // 驱动模式 + 替换现有程序
    // err = bpf_xdp_attach(ifindex, prog_fd, opts_flags, NULL);
    // if (err < 0) {
    //     fprintf(stderr, "Attach XDP in native mode failed: %s\n", strerror(-err));
    //     goto cleanup;
    // }

    // 2. 初始化事件处理
    // ============================================
    map_fd = bpf_map__fd(map);
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Create ring buffer failed\n");
        goto cleanup;
    }

    printf("XDP program loaded. Start processing events...\n");
    
    // 3. 主事件循环
    // ============================================
    while (true) {
        // 轮询事件。读取到的报文会被传递到第2步中指定的handle_event函数
        err = ring_buffer__poll(rb, 1000 /* timeout_ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            printf("Poll error: %d\n", err);
            break;
        }
    }

cleanup:
    sig_handler(0);
    return 0;
}