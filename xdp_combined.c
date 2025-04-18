// xdp_combined.c
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>

#define BPF_FILE "dart_filter_kern.o"
#define PIN_PATH "/sys/fs/bpf/events"
#define MAX_RINGBUF_ENTRIES (1 << 24) // 16 MB ring buffer  
#define MAX_RINGBUF_POLL_TIMEOUT 1000 // 1 second


static struct bpf_object *obj = NULL;
static struct bpf_link *xdp_link = NULL;
static struct ring_buffer *rb = NULL;

struct dart_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned char dart_version;
    unsigned char dart_proto;
};

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
    struct dart_event *e = data;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &e->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &e->dst_ip, dst_ip, sizeof(dst_ip));
    
    printf("DART Event: %s -> %s  Version: %u  Proto: %u\n",
           src_ip, dst_ip, e->dart_version, e->dart_proto);

    // 检查是否是ICMP REQUEST
    if (e->dart_proto == IPPROTO_ICMP) {
        printf("ICMP Request detected. Preparing response...\n");

        // 构造响应逻辑
        struct dart_event response;
        response.src_ip = e->dst_ip; // 交换源和目标IP
        response.dst_ip = e->src_ip;
        response.dart_version = e->dart_version;
        response.dart_proto = e->dart_proto;

        // 发送响应逻辑（假设有一个函数 send_response 实现发送）
        if (send_response(&response) < 0) {
            fprintf(stderr, "Failed to send ICMP response\n");
        } else {
            printf("ICMP Response sent: %s -> %s\n", dst_ip, src_ip);
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int ifindex, map_fd;
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