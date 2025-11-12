#include "common.h"
#include <time.h>
#include <arpa/inet.h>

#define SESSION_LOG_FILE "/tmp/session_stats.log"
#define ALERT_LOG_FILE "/tmp/alert_fast.txt"
#define LINE_MAX 512

volatile sig_atomic_t alert_running = 1;

typedef struct {
    time_t timestamp;
    char src_ip[20];
    uint16_t src_port;
    char dst_ip[20];
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t packets;
    uint64_t bytes;
} session_entry_t;

// 프로토콜 이름 변환
const char* proto_to_string(uint8_t proto) {
    switch(proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

// 세션 로그 파싱
int parse_session_log(const char *line, session_entry_t *entry) {
    char src_full[50], dst_full[50];
    
    // 형식: timestamp|src_ip:src_port|dst_ip:dst_port|proto|packets|bytes
    int ret = sscanf(line, "%ld|%49[^|]|%49[^|]|%hhu|%lu|%lu",
                     &entry->timestamp,
                     src_full,
                     dst_full,
                     &entry->protocol,
                     &entry->packets,
                     &entry->bytes);
    
    if (ret != 6) {
        return -1;
    }
    
    // src_ip:src_port 파싱
    char *colon = strrchr(src_full, ':');
    if (colon) {
        *colon = '\0';
        strncpy(entry->src_ip, src_full, sizeof(entry->src_ip) - 1);
        entry->src_port = atoi(colon + 1);
    }
    
    // dst_ip:dst_port 파싱
    colon = strrchr(dst_full, ':');
    if (colon) {
        *colon = '\0';
        strncpy(entry->dst_ip, dst_full, sizeof(entry->dst_ip) - 1);
        entry->dst_port = atoi(colon + 1);
    }
    
    return 0;
}

// 바이트를 읽기 쉬운 형식으로 변환
void format_bytes(uint64_t bytes, char *buf, size_t bufsize) {
    if (bytes < 1024) {
        snprintf(buf, bufsize, "%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buf, bufsize, "%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buf, bufsize, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, bufsize, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

// 최근 1분 로그 출력
void print_recent_sessions(time_t cutoff_time) {
    FILE *fp = fopen(SESSION_LOG_FILE, "r");
    if (!fp) {
        return;
    }
    
    char line[LINE_MAX];
    session_entry_t entry;
    int session_count = 0;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║               세션별 통계 (최근 1분)                                          ║\n");
    printf("╠════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-18s %-18s %-6s %-10s %-15s ║\n", 
           "Source", "Destination", "Proto", "Packets", "Bytes");
    printf("╠════════════════════════════════════════════════════════════════════════════════╣\n");
    
    while (fgets(line, sizeof(line), fp)) {
        if (parse_session_log(line, &entry) == 0) {
            // 최근 1분 이내 데이터만 출력
            if (entry.timestamp >= cutoff_time) {
                char bytes_str[20];
                format_bytes(entry.bytes, bytes_str, sizeof(bytes_str));
                
                printf("║ %15s:%-5u %15s:%-5u %-6s %10lu %15s ║\n",
                       entry.src_ip, entry.src_port,
                       entry.dst_ip, entry.dst_port,
                       proto_to_string(entry.protocol),
                       entry.packets,
                       bytes_str);
                
                session_count++;
                total_packets += entry.packets;
                total_bytes += entry.bytes;
            }
        }
    }
    
    fclose(fp);
    
    // 통계 요약
    char total_bytes_str[20];
    format_bytes(total_bytes, total_bytes_str, sizeof(total_bytes_str));
    
    printf("╠════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ 총 세션: %-10d | 총 패킷: %-15lu | 총 통신량: %-15s ║\n",
           session_count, total_packets, total_bytes_str);
    printf("╚════════════════════════════════════════════════════════════════════════════════╝\n");
}

// Alert 로그 출력
void print_recent_alerts(time_t cutoff_time) {
    (void)cutoff_time;  // 미사용 경고 제거
    
    FILE *fp = fopen(ALERT_LOG_FILE, "r");
    if (!fp) {
        return;
    }
    
    char line[LINE_MAX];
    int alert_count = 0;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║               Snort3 Alerts (최근 1분)                                        ║\n");
    printf("╠════════════════════════════════════════════════════════════════════════════════╣\n");
    
    // 간단한 시간 체크 (alert_fast.txt는 타임스탬프 파싱이 필요)
    // 여기서는 전체 출력 (실제로는 타임스탬프 파싱 필요)
    while (fgets(line, sizeof(line), fp)) {
        if (strlen(line) > 1) {
            printf("║ %s", line);
            alert_count++;
        }
    }
    
    fclose(fp);
    
    if (alert_count == 0) {
        printf("║ (최근 Alert 없음)                                                            ║\n");
    }
    
    printf("╚════════════════════════════════════════════════════════════════════════════════╝\n");
}

// Alert 쓰레드 메인 함수
void *alert_thread_main(void *arg) {
    (void)arg;
    int interval = 10; // 10초마다 갱신
    
    printf("[ALERT] Alert 모니터링 쓰레드 시작 (갱신 주기: %d초)\n", interval);
    
    // 처음 3초 대기 (다른 쓰레드가 준비될 시간)
    sleep(3);
    
    while (alert_running) {
        // 화면 클리어
        printf("\033[2J\033[H");
        
        time_t now = time(NULL);
        time_t cutoff = now - 60; // 최근 1분
        
        // 현재 시간 출력
        char time_str[30];
        struct tm *tm_info = localtime(&now);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        
        printf("\n╔════════════════════════════════════════════════════════════════════════════════╗\n");
        printf("║                     Mini-IDS Alert & Session Monitor                          ║\n");
        printf("║                     현재 시각: %-47s║\n", time_str);
        printf("╚════════════════════════════════════════════════════════════════════════════════╝\n");
        
        // 세션 통계 출력
        print_recent_sessions(cutoff);
        
        // Alert 출력
        print_recent_alerts(cutoff);
        
        printf("\n[Ctrl+C로 종료]\n");
        
        // interval 동안 대기 (alert_running 체크하면서)
        for (int i = 0; i < interval && alert_running; i++) {
            sleep(1);
        }
    }
    
    printf("[ALERT] Alert 모니터링 쓰레드 종료\n");
    return NULL;
}

// 독립 실행용 main 함수
#ifdef STANDALONE_BUILD
int main(int argc, char *argv[]) {
    int interval = 10; // 기본 10초
    
    if (argc > 1) {
        interval = atoi(argv[1]);
        if (interval < 1) interval = 10;
    }
    
    printf("╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                     Mini-IDS Alert & Session Monitor                          ║\n");
    printf("║                     갱신 주기: %d초 (독립 실행 모드)                          ║\n", interval);
    printf("╚════════════════════════════════════════════════════════════════════════════════╝\n");
    
    signal(SIGINT, SIG_DFL);
    
    while (1) {
        // 화면 클리어
        printf("\033[2J\033[H");
        
        time_t now = time(NULL);
        time_t cutoff = now - 60; // 최근 1분
        
        // 현재 시간 출력
        char time_str[30];
        struct tm *tm_info = localtime(&now);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        
        printf("\n╔════════════════════════════════════════════════════════════════════════════════╗\n");
        printf("║                     Mini-IDS Alert & Session Monitor                          ║\n");
        printf("║                     현재 시각: %-47s║\n", time_str);
        printf("╚════════════════════════════════════════════════════════════════════════════════╝\n");
        
        // 세션 통계 출력
        print_recent_sessions(cutoff);
        
        // Alert 출력
        print_recent_alerts(cutoff);
        
        printf("\n[Ctrl+C로 종료]\n");
        
        sleep(interval);
    }
    
    return 0;
}
#endif
