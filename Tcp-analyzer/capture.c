#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "session.h"

typedef unsigned char u_char;

//함수 선언
void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet);



void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    packet_capture(pkthdr, packet);
}



unsigned int hash_session(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    return (src_ip ^ dst_ip ^ src_port ^ dst_port) % HASH_TABLE_SIZE;
}




void packet_analyze(const char *key, const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const struct pcap_pkthdr *pkthdr)
{
uint8_t flags = tcp_hdr->th_flags;

if ((flags & TH_SYN) && !(flags & TH_ACK)) {
printf("[SYN] Start session: %s\n", key);
// 세션 목록에 추가 (세션 상태 = SYN_SENT)
}
else if ((flags & TH_SYN) && (flags & TH_ACK)) {
printf("[SYN-ACK] From: %s\n", key);
// 세션 상태 = SYN_RECEIVED
}
else if ((flags & TH_ACK)) {
printf("[ACK] Ongoing session: %s\n", key);
// 세션 상태 = ESTABLISHED
}

// 이후 데이터, 종료 패킷(=FIN, RST) 등에 따라 추가 분석 가능
}


void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;

    // Ethernet 헤더는 14바이트
    ip_hdr = (struct ip*)(packet + 14);

    // IP가 TCP인지 확인
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + ip_hdr_len);

    // 5-튜플 정보 추출
    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    // 해시 키 생성 (문자열 기반)
    char session_key[128];
    snprintf(session_key, sizeof(session_key), "%s:%d-%s:%d",
             inet_ntoa(ip_hdr->ip_src), src_port,
             inet_ntoa(ip_hdr->ip_dst), dst_port);

    // 세션 분석 함수로 위임
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