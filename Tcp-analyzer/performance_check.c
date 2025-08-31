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

//데이터 RTT 계산 (시간 차이)
void calculate_data_rtt(session_t *session, const struct pcap_pkthdr *pkthdr, uint32_t seq, uint32_t ack_seq) {
    if (!session) return;

    // 세션 내 중복 여부: 1(중복 아님), 2(중복 감지)
    if (session->duplicate_flag != 2)
        session->duplicate_flag = 1;

    // 데이터 패킷 송신 시 최근 SEQ 배열에 저장 및 재전송 탐지
    if (seq != 0) {
        bool retransmission = false;
        for (int i = 0; i < MAX_RECENT_SEQ; i++) {
            if (session->recent_seq[i].seq == seq) {
                // 중복(재전송) 감지 시 2로 설정 (한 번이라도 2가 되면 계속 2)
                session->retransmission_count++;
                session->duplicate_flag = 2;
                retransmission = true;
                break;
            }
        }
        if (!retransmission) {
            for (int i = 0; i < MAX_RECENT_SEQ; i++) {
                if (session->recent_seq[i].seq == 0) {
                    session->recent_seq[i].seq = seq;
                    session->recent_seq[i].send_time = pkthdr->ts;
                    break;
                }
            }
        }
    }
    // ACK 패킷 도착 시 해당 SEQ와 매칭되는 송신 시각 찾아 RTT 계산
    for (int i = 0; i < MAX_RECENT_SEQ; i++) {
        if (session->recent_seq[i].seq == ack_seq) {
            session->data_rtt = timeval_diff_in_seconds(&session->recent_seq[i].send_time, (struct timeval*)&pkthdr->ts);
            session->recent_seq[i].seq = 0; // 사용 후 초기화
            break;
        }
    }
}

// 처리율(Throughput) 계산(시간
double calculate_throughput(const session_t *session, double duration_seconds) {
    if (!session || duration_seconds <= 0.0) return 0.0;
    return session->byte_count / duration_seconds; // bytes per second
}


// 출력 중복 확인
void print_session_report(session_t *session) {
    if (!session || session->report_printed) return;

    print_performance_report(session, stdout);
    session->report_printed = true;
}



void print_performance_report(const session_t *session, FILE *fp) {
    if (!session) return;

    // 파일 출력 (session_report.csv)
    fprintf(fp, "%u,%u,%u,%u,%.6f,%.6f,%u,%u,%.2f,%d\n",
        session->key.src_ip, session->key.src_port,
        session->key.dst_ip, session->key.dst_port,
        session->handshake_rtt, session->data_rtt,
        session->packet_count, session->byte_count,
        calculate_throughput(session, 60.0),
        session->duplicate_flag // 1: 정상, 2: 중복
    );
    
    printf("================== Session Info =================\n");
    printf("Session %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           (session->key.src_ip >> 24) & 0xFF, (session->key.src_ip >> 16) & 0xFF,
           (session->key.src_ip >> 8) & 0xFF, session->key.src_ip & 0xFF,
           session->key.src_port,
           (session->key.dst_ip >> 24) & 0xFF, (session->key.dst_ip >> 16) & 0xFF,
           (session->key.dst_ip >> 8) & 0xFF, session->key.dst_ip & 0xFF,
           session->key.dst_port);
    printf("\n================= Performance Report ================\n");
    printf("Handshake RTT: %.6f sec\n", session->handshake_rtt);
    printf("Data RTT: %.6f sec\n", session->data_rtt);
    printf("Packets: %u, Bytes: %u\n", session->packet_count, session->byte_count);
    printf("Retransmissions: %u\n", session->retransmission_count);
    double throughput = calculate_throughput(session, 60.0);
    printf("Throughput: %.2f bytes/sec\n", throughput);
    printf("=====================================================\n\n");
}

