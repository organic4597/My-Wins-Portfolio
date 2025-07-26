#ifndef SESSION_H
#define SESSION_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <time.h>

#define MAX_SESSIONS 1024

typedef struct session {
    char key[128];  // "src_ip:src_port->dst_ip:dst_port"
    struct timeval start_time;
    struct timeval last_time;
    uint32_t packet_count;
    uint32_t byte_count;
    struct session *next;
} session_t;

typedef struct {
    session_t *buckets[MAX_SESSIONS];
} session_table_t;

unsigned int hash_key(const char *key);
session_t *session_table_lookup(session_table_t *table, const char *key);
session_t *session_table_insert(session_table_t *table, const char *key, const struct pcap_pkthdr *pkthdr);

#endif
