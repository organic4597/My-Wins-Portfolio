#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <string.h>
#include "performance_check.h"
#include "session.h"
#define unsigned_char u_char
#define SESSION_TABLE_SIZE 1024
FILE *fp = NULL; // static으로 선언



//함수 선언
void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet);

//패킷 핸들러
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    packet_capture(pkthdr, packet);
}


//세션 테이블에서 해쉬값 호출&(패킷 정보)출력
// session_table_t를 전역 또는 static으로 선언하는 부분 유지
static session_table_t session_table = {0};  // static 선언은 한 곳에만 있어야 함

void packet_analyze(const session_key_t *key, const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const struct pcap_pkthdr *pkthdr) {
    session_t *session = session_table_insert(&session_table, key, pkthdr);
    if (!session) return;

    session->packet_count++;
    session->byte_count += ntohs(ip_hdr->ip_len);
    session->last_time = pkthdr->ts;

    // 3-way 핸드쉐이크 RTT 계산
    calculate_handshake_rtt(session, pkthdr, tcp_hdr->th_flags);

    // 데이터 RTT 계산
    calculate_data_rtt(session, pkthdr, ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));

    if ((tcp_hdr->th_flags & TH_FIN || tcp_hdr->th_flags & TH_RST) && !session->report_printed) {
        print_performance_report(session, fp);
        session->report_printed = true;
    }

    /*if (session) {
        printf("[Session] src=%s:%u dst=%s:%u - Packets: %u, Bytes: %u, Duration: %.3f sec\n",
            inet_ntoa(*(struct in_addr *)&session->key.src_ip), ntohs(session->key.src_port),
            inet_ntoa(*(struct in_addr *)&session->key.dst_ip), ntohs(session->key.dst_port),
            session->packet_count,
            session->byte_count,
            (session->last_time.tv_sec - session->start_time.tv_sec) +
            (session->last_time.tv_usec - session->start_time.tv_usec) / 1000000.0);
    }*/
}

void packet_capture(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14);
    //이더넷 헤더 14바이트 건너뜀

    if (ip_hdr->ip_p != IPPROTO_TCP) return;
    //바이트 길이만큼 할당해줌
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    session_key_t key;
    key.src_ip = ip_hdr->ip_src.s_addr;
    key.dst_ip = ip_hdr->ip_dst.s_addr;
    key.src_port = tcp_hdr->th_sport; 
    key.dst_port = tcp_hdr->th_dport;

    // 네트워크 바이트 순서(ntohs) 적용
    key.src_port = ntohs(key.src_port);
    key.dst_port = ntohs(key.dst_port);

    packet_analyze(&key, ip_hdr, tcp_hdr, pkthdr);
}



int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "eth0"; // 캡처할 네트워크 인터페이스 이름 (예: eth0)
    int snaplen = 65535;      // 최대 패킷 크기
    int promisc = 1;          // promiscuous mode (모든 패킷 캡처)
    int timeout_ms = 1000;    // 버퍼 타임아웃 (ms)

    fp = fopen("session_report.csv", "w");
    fprintf(fp, "src_ip,src_port,dst_ip,dst_port,handshake_rtt,data_rtt,packets,bytes,throughput,duplicate\n"); // 헤더

    handle = pcap_open_live(dev, snaplen, promisc, timeout_ms, errbuf);
    if (handle == NULL)
    {
        printf("pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    fclose(fp);
}