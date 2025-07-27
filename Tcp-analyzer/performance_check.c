#include "performance_check.h"
#include <stdio.h>
#include <sys/time.h>

static double timeval_diff_in_seconds(struct timeval *start, struct timeval *end) {
    return (double)(end->tv_sec - start->tv_sec) + (double)(end->tv_usec - start->tv_usec) / 1000000.0;
}

// 3-way handshake RTT 계산 
void calculate_handshake_rtt(session_t *session, const struct pcap_pkthdr *pkthdr, uint8_t tcp_flags) {
    if (!session) return;

    // SYN 패킷 도착 시각 저장
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
        session->syn_time = pkthdr->ts;
    }
    // SYN-ACK 패킷 도착 시각 저장 및 RTT 계산
    else if ((tcp_flags & TH_SYN) && (tcp_flags & TH_ACK)) {
        session->syn_ack_time = pkthdr->ts;
        session->handshake_rtt = timeval_diff_in_seconds(&session->syn_time, &session->syn_ack_time);
    }
}

//데이터 RTT 계산
void calculate_data_rtt(session_t *session, const struct pcap_pkthdr *pkthdr, uint32_t seq, uint32_t ack_seq) {
    if (!session) return;

    // 데이터 패킷 송신 시각 기록 (가장 최근 SEQ)
    if (seq != 0 && seq != session->last_seq) {
        session->last_seq = seq;
        session->seq_send_time = pkthdr->ts;
    }
    // ACK 패킷 도착 시 송신 시각과 비교해 RTT 계산
    else if (ack_seq == session->last_seq) {
        session->data_rtt = timeval_diff_in_seconds(&session->seq_send_time, (struct timeval*)&pkthdr->ts);
    }
}

// 처리율(Throughput) 계산
double calculate_throughput(const session_t *session, double duration_seconds) {
    if (!session || duration_seconds <= 0.0) return 0.0;
    return session->byte_count / duration_seconds; // bytes per second
}

void print_session_report(session_t *session) {
    if (!session || session->report_printed) return;

    print_performance_report(session);
    session->report_printed = true;
}



void print_performance_report(const session_t *session) {
    if (!session) return;

    printf("Session %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           (session->key.src_ip >> 24) & 0xFF, (session->key.src_ip >> 16) & 0xFF,
           (session->key.src_ip >> 8) & 0xFF, session->key.src_ip & 0xFF,
           session->key.src_port,
           (session->key.dst_ip >> 24) & 0xFF, (session->key.dst_ip >> 16) & 0xFF,
           (session->key.dst_ip >> 8) & 0xFF, session->key.dst_ip & 0xFF,
           session->key.dst_port);

    printf("Handshake RTT: %.6f sec\n", session->handshake_rtt);
    printf("Data RTT: %.6f sec\n", session->data_rtt);
    printf("Packets: %u, Bytes: %u\n", session->packet_count, session->byte_count);

    double throughput = calculate_throughput(session, 60.0);
    printf("Throughput: %.2f bytes/sec\n", throughput);
}

