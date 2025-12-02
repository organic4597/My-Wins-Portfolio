#ifndef ALERT_MONITOR_H
#define ALERT_MONITOR_H

#include <stdint.h>
#include <time.h>
#include <signal.h>

// Alert Monitor 설정
#define SESSION_LOG_FILE "/tmp/session_stats.log"
#define ALERT_LOG_FILE   "/tmp/alert_fast.txt"
#define TOP_N 20
#define MAX_ENTRIES 10000
#define LINE_MAX 1024

// 통합 엔트리 구조체
typedef struct {
    time_t timestamp;
    char src_ip[64];
    uint16_t src_port;
    char dst_ip[64];
    uint16_t dst_port;
    int protocol;
    uint64_t packets;
    uint64_t bytes;
    int has_alert;
    char alert_msg[256];
    double score;
} combined_entry_t;

// Alert monitor 쓰레드 메인 함수
void *alert_monitor_thread_main(void *arg);

// 전역 제어 변수
extern volatile sig_atomic_t alert_running;

#endif // ALERT_MONITOR_H
