#ifndef COMMON_H
#define COMMON_H

// Feature test macros (맨 위!)
#define _BSD_SOURCE
#define _DEFAULT_SOURCE

// 표준 C 라이브러리
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// POSIX/시스템 헤더
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

// 네트워크 관련
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

// 외부 라이브러리
#include <pcap.h>

// UDS 경로
#define UDS_SOCKET_PATH "/tmp/mini_ids_packets.sock"
#define SNAP_LEN 65535

// UDS 전송 패킷
typedef struct {
    uint32_t packet_len;              // 패킷 길이
    uint64_t timestamp_sec;           // 타임스탬프 (초)
    uint32_t timestamp_usec;          // 타임스탬프 (마이크로초)
    uint8_t packet_data[SNAP_LEN];    // 패킷 원시 데이터
} uds_packet_t;


extern int uds_socket;
extern volatile sig_atomic_t running;

#endif // COMMON_H




