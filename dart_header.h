#include <stdint.h>

#define IPPROTO_DART 254

typedef struct {
    uint8_t version;
    uint8_t protocol_number; // 上层协议号
    uint8_t dest_addr_len;   // 目标地址长度
    uint8_t src_addr_len;    // 源地址长度
    // char *dest_addr;         // 目标地址（改为char*）
    // char *src_addr;          // 源地址（改为char*）
} dart_packet_t;