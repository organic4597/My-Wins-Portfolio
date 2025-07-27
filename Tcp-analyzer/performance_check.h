#ifndef PERFORMANCE_CHECK_H
#define PERFORMANCE_CHECK_H

#include "session.h"
#include <pcap.h>


// 3-way handshake RTT 계산 (SYN, SYN-ACK 시각 차이 저장)
void calculate_handshake_rtt(session_t *session, const struct pcap_pkthdr *pkthdr, uint8_t tcp_flags);

// 데이터 RTT 계산 (특정 SEQ 전송 시각과 ACK 시각 차이 계산)
void calculate_data_rtt(session_t *session, const struct pcap_pkthdr *pkthdr, uint32_t seq, uint32_t ack_seq);

// 성능 지표 출력 함수
void print_performance_report(const session_t *session);

// 출력 중복 확인 함수
void print_session_report(session_t *session); 

#endif
