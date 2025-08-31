#ifndef SESSION_H
#define SESSION_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>


#define MAX_SESSIONS 1024
#define MAX_RECENT_SEQ 8

typedef struct {
    uint32_t seq;
    struct timeval send_time;
} seq_time_t;
typedef struct session_key_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} session_key_t;

typedef struct session {
    session_key_t key;         // 5-튜플 세션 키
    struct timeval start_time;
    struct timeval last_time;
    uint32_t packet_count;
    uint32_t byte_count;
    seq_time_t recent_seq[MAX_RECENT_SEQ];

    // RTT 계산 관련 필드
    struct timeval syn_time;       // SYN 패킷 타임스탬프
    struct timeval syn_ack_time;   // SYN/ACK 패킷 타임스탬프
    double handshake_rtt;          // 핸드쉐이크 RTT (초)

    // 데이터 전송 RTT 계산용
    uint32_t last_seq;             // 마지막 관찰 SEQ 번호
    struct timeval seq_send_time;  // 마지막 SEQ 전송 시간
    double data_rtt;               // 데이터 RTT (초)

    // 처리율(Throughput) 계산 관련 필드
    uint64_t bytes_sent_total;     // 세션 동안 전송된 총 바이트 수
    double throughput;             // 처리율 (bps 등으로 계산 가능)

    // TCP 재전송 탐지 관련 필드
    uint32_t retransmission_count; // 재전송된 패킷 수
    int duplicate_flag; // 1: 정상, 2: 중복(재전송 감지)

    bool report_printed; // 이미 리포트를 출력했는지
    bool is_duplicate; // 중복 세션 여부 추가

    struct session *next;
} session_t;

typedef struct {
    session_t *buckets[MAX_SESSIONS];
} session_table_t;

// 해시 함수 (5-튜플 구조체 기반)
unsigned int hash_session_key(const session_key_t *key);

// 키 비교 함수
int session_key_equal(const session_key_t *a, const session_key_t *b); 

// 세션 테이블 조회 및 삽입 함수 (5-튜플 키 사용)
session_t *session_table_lookup(session_table_t *table, const session_key_t *key);
session_t *session_table_insert(session_table_t *table, const session_key_t *key, const struct pcap_pkthdr *pkthdr);

#endif
