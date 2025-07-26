#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "session.h"

unsigned int hash_key(const char *key) {
    unsigned int hash = 5381;
    int c;
    while ((c = *key++))
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    return hash % MAX_SESSIONS;
}

session_t *session_table_lookup(session_table_t *table, const char *key) {
    unsigned int index = hash_key(key);
    session_t *current = table->buckets[index];
    while (current != NULL) {
        if (strcmp(current->key, key) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

session_t *session_table_insert(session_table_t *table, const char *key, const struct pcap_pkthdr *pkthdr) {
    session_t *existing = session_table_lookup(table, key);
    if (existing != NULL) {
        // 이미 존재하면 업데이트만
        existing->packet_count++;
        existing->byte_count += pkthdr->caplen;
        existing->last_time = pkthdr->ts;
        return existing;
    }

    // 새 세션 생성
    session_t *new_session = (session_t *)malloc(sizeof(session_t));
    if (!new_session) {
        fprintf(stderr, "Memory allocation failed for new session\n");
        return NULL;
    }
    strncpy(new_session->key, key, sizeof(new_session->key));
    new_session->start_time = pkthdr->ts;
    new_session->last_time = pkthdr->ts;
    new_session->packet_count = 1;
    new_session->byte_count = pkthdr->caplen;
    new_session->next = NULL;

    // 해시 버킷에 삽입
    unsigned int index = hash_key(key);
    new_session->next = table->buckets[index];
    table->buckets[index] = new_session;

    return new_session;
}
