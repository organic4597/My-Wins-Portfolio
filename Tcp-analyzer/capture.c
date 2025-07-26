#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <string.h>
#include "session.h"
#define unsigned_char u_char
#define SESSION_TABLE_SIZE 1024

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
} session_key_t;



//함수 선언
void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet);

//5-튜링 해시 함수
unsigned int hash_session_key(const session_key_t *key) {
    return (key->src_ip ^ key->dst_ip ^ key->src_port ^ key->dst_port) % SESSION_TABLE_SIZE;
}

//패킷 핸들러
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    packet_capture(pkthdr, packet);
}



void packet_analyze(const char *key, const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const struct pcap_pkthdr *pkthdr) {
    static session_table_t session_table = {0};  // 정적 선언

    session_t *session = session_table_insert(&session_table, key, pkthdr);
    if (session) {
        printf("[Session] %s - Packets: %u, Bytes: %u, Duration: %.3f sec\n",
            session->key,
            session->packet_count,
            session->byte_count,
            (session->last_time.tv_sec - session->start_time.tv_sec) +
            (session->last_time.tv_usec - session->start_time.tv_usec) / 1000000.0);
    }
}



//패킷 캡쳐 및 세션 추가 
void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14);

    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    char session_key[128];
    snprintf(session_key, sizeof(session_key), "%s:%d-%s:%d",
             inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
             inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));

    packet_analyze(session_key, ip_hdr, tcp_hdr, pkthdr);
}



int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *filepath = "./pcap_log/test.pcap";
    
    handle = pcap_open_offline(filepath, errbuf);
    if (handle == NULL)
    {
        printf("pcap_open_offline() failed: %c\n", errbuf);
    } 

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

}