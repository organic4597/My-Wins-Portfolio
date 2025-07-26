#ifndef SESSION_H
#define SESSION_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>

#define HASH_TABLE_SIZE 4096

typedef struct session_key {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} session_key_t;

typedef struct session_data {
    session_key_t key;
    uint32_t last_seq;
    int retransmissions;
    time_t start_time;
    time_t end_time;
    int packet_count;
    struct session_data* next;  // 해시 충돌 해결용 체이닝
} session_data_t;

// 해시 기반 세션 테이블
extern session_data_t* session_table[HASH_TABLE_SIZE];

// 함수 선언
void init_session_table();
unsigned int hash_session_key(session_key_t* key);
session_data_t* find_or_create_session(struct ip* ip_hdr, struct tcphdr* tcp_hdr);
void update_session(session_data_t* session, struct tcphdr* tcp_hdr);
void dup_detection(session_data_t* session, struct tcphdr* tcp_hdr);
void print_all_sessions();
void free_session_table();

#endif
