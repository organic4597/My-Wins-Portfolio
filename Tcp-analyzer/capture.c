#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
typedef unsigned char u_char;

//함수 선언
void packet_cap(const struct pcap_pkthdr *pkthdr, const u_char *packet);



void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    packet_cap(pkthdr, packet);
}


void packet_cap(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;

    // Ethernet 헤더는 14바이트
    ip_hdr = (struct ip*)(packet + 14); //아이피 주소

    // IP가 TCP인지 확인
    if (ip_hdr->ip_p != IPPROTO_TCP) return;
소
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + ip_hdr_len);

    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    // TCP flag
    uint8_t flags = tcp_hdr->th_flags;
    if ((flags & TH_SYN) && !(flags & TH_ACK)) 
    {
        printf("SYN from %s:%d to %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), src_port,
            inet_ntoa(ip_hdr->ip_dst), dst_port);
    }
    else if ((flags & TH_SYN) && (flags & TH_ACK)) 
    {
        printf("SYN-ACK from %s:%d to %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), src_port,
            inet_ntoa(ip_hdr->ip_dst), dst_port);
    }
    else if ((flags & TH_ACK)) 
    {
        printf("ACK from %s:%d to %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), src_port,
            inet_ntoa(ip_hdr->ip_dst), dst_port);
    }
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