#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "session.h"

// 방향 무관 5-튜플 해시 함수
unsigned int hash_session_key(const session_key_t *key) {
    // IP, 포트 순서가 바뀌어도 같은 결과를 내도록 정렬
    uint32_t ip1 = key->src_ip < key->dst_ip ? key->src_ip : key->dst_ip;
    uint32_t ip2 = key->src_ip < key->dst_ip ? key->dst_ip : key->src_ip;

    uint16_t port1 = key->src_port < key->dst_port ? key->src_port : key->dst_port;
    uint16_t port2 = key->src_port < key->dst_port ? key->dst_port : key->src_port;

    return (ip1 ^ ip2 ^ port1 ^ port2) % MAX_SESSIONS;
}

// 방향 무관 세션 키 비교 함수
int session_key_equal(const session_key_t *a, const session_key_t *b) {
    return ((a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
             a->src_port == b->src_port && a->dst_port == b->dst_port) ||

            (a->src_ip == b->dst_ip && a->dst_ip == b->src_ip &&
             a->src_port == b->dst_port && a->dst_port == b->src_port));
}

// 세션 테이블에서 세션 조회
session_t *session_table_lookup(session_table_t *table, const session_key_t *key) {
    unsigned int index = hash_session_key(key);
    session_t *current = table->buckets[index];
    while (current != NULL) {
        if (session_key_equal(&current->key, key))
            return current;
        current = current->next;
    }
    return NULL;
}

// 세션 테이블에 세션 삽입 (없으면 새로 생성, 있으면 업데이트)
session_t *session_table_insert(session_table_t *table, const session_key_t *key, const struct pcap_pkthdr *pkthdr) {
    session_t *existing = session_table_lookup(table, key);
    if (existing != NULL) {
        // 기존 세션 정보 업데이트
        existing->packet_count++;
        existing->byte_count += pkthdr->caplen;
        existing->last_time = pkthdr->ts;
        return existing;
    }

    // 새로운 세션 생성
    session_t *new_session = (session_t *)malloc(sizeof(session_t));
    if (!new_session) {
        fprintf(stderr, "Memory allocation failed for new session\n");
        return NULL;
    }

    // 키 복사 및 초기화
    new_session->key = *key;
    new_session->start_time = pkthdr->ts;
    new_session->last_time = pkthdr->ts;
    new_session->packet_count = 1;
    new_session->byte_count = pkthdr->caplen;
    new_session->next = NULL;

    // 해시 버킷에 삽입
    unsigned int index = hash_session_key(key);
    new_session->next = table->buckets[index];
    table->buckets[index] = new_session;

    return new_session;
}
