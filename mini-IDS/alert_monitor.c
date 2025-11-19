#include "alert_monitor.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

volatile sig_atomic_t alert_running = 1;

// 프로토콜 이름 변환
static const char* proto_to_string(int proto) {
    switch(proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

// 세션 로그 파싱
static int parse_session_log(const char *line, combined_entry_t *entry) {
    char src_full[50], dst_full[50];
    unsigned char proto_tmp;
    
    // 형식: timestamp|src_ip:src_port|dst_ip:dst_port|proto|packets|bytes
    int ret = sscanf(line, "%ld|%49[^|]|%49[^|]|%hhu|%lu|%lu",
                     &entry->timestamp,
                     src_full,
                     dst_full,
                     &proto_tmp,
                     &entry->packets,
                     &entry->bytes);
    
    if (ret != 6) {
        return -1;
    }
    
    entry->protocol = proto_tmp;
    
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
    
    entry->has_alert = 0;
    entry->alert_msg[0] = '\0';
    
    return 0;
}

// Alert 로그 파싱
static int parse_alert_log(const char *line, char *src_ip, char *dst_ip, char *alert_msg, size_t msg_size) {
    // Snort alert 형식: 11/19-23:02:13.962352 [**] [1:1000003:1] "message" [**] [Priority: 0] {TCP} 192.168.0.102:55331 -> 23.50.121.170:443
    
    // Alert 메시지 추출 (먼저)
    char *msg_start = strstr(line, "] \"");
    if (msg_start) {
        msg_start += 3;  // '] "' 건너뛰기
        char *msg_end = strchr(msg_start, '"');
        if (msg_end) {
            size_t len = msg_end - msg_start;
            if (len >= msg_size) len = msg_size - 1;
            strncpy(alert_msg, msg_start, len);
            alert_msg[len] = '\0';
        }
    } else {
        alert_msg[0] = '\0';
    }
    
    // IP 주소 추출: {TCP} 192.168.0.102:55331 -> 23.50.121.170:443
    char *proto_start = strchr(line, '{');
    if (proto_start) {
        char *arrow = strstr(proto_start, " -> ");
        if (arrow) {
            // 출발지 IP:port 추출
            char *src_start = proto_start;
            while (*src_start && !isdigit(*src_start)) src_start++;
            
            if (src_start && *src_start) {
                // IP:port에서 IP만 추출
                char src_full[50];
                sscanf(src_start, "%49s", src_full);
                
                // ':' 찾아서 IP만 복사
                char *colon = strchr(src_full, ':');
                if (colon) {
                    *colon = '\0';
                }
                strncpy(src_ip, src_full, 19);
                src_ip[19] = '\0';
                
                // 목적지 IP:port 추출
                char dst_full[50];
                sscanf(arrow + 4, "%49s", dst_full);
                
                colon = strchr(dst_full, ':');
                if (colon) {
                    *colon = '\0';
                }
                strncpy(dst_ip, dst_full, 19);
                dst_ip[19] = '\0';
                
                return 0;
            }
        }
    }
    
    return -1;
}

// 스코어 계산
static double calculate_score(const combined_entry_t *entry) {
    double score = 0.0;
    
    if (entry->has_alert) {
        score += 1000.0;
    }
    
    score += entry->packets * 10.0;
    score += (entry->bytes / 1024.0);
    
    return score;
}

// 바이트 포맷팅
static void format_bytes(uint64_t bytes, char *buf, size_t bufsize) {
    if (bytes < 1024) {
        snprintf(buf, bufsize, "%luB", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buf, bufsize, "%.1fKB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buf, bufsize, "%.1fMB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, bufsize, "%.1fGB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

// qsort 비교 함수
static int compare_score(const void *a, const void *b) {
    const combined_entry_t *ea = (const combined_entry_t *)a;
    const combined_entry_t *eb = (const combined_entry_t *)b;
    
    if (eb->score > ea->score) return 1;
    if (eb->score < ea->score) return -1;
    return 0;
}

// Top N 위협 출력
static void print_top_threats(time_t cutoff_time) {
    combined_entry_t *entries = malloc(sizeof(combined_entry_t) * MAX_ENTRIES);
    if (!entries) {
        fprintf(stderr, "[ALERT_MONITOR] 메모리 할당 실패\n");
        return;
    }
    
    int count = 0;
    
    // 1. 세션 통계 로드
    FILE *fp = fopen(SESSION_LOG_FILE, "r");
    if (fp) {
        char line[LINE_MAX];
        combined_entry_t temp;
        while (fgets(line, sizeof(line), fp)) {
            if (parse_session_log(line, &temp) == 0) {
                if (temp.timestamp >= cutoff_time) {
                    // 중복 세션 확인 및 병합
                    int found = -1;
                    for (int i = 0; i < count; i++) {
                        if (strcmp(entries[i].src_ip, temp.src_ip) == 0 &&
                            entries[i].src_port == temp.src_port &&
                            strcmp(entries[i].dst_ip, temp.dst_ip) == 0 &&
                            entries[i].dst_port == temp.dst_port &&
                            entries[i].protocol == temp.protocol) {
                            found = i;
                            break;
                        }
                    }
                    
                    if (found >= 0) {
                        entries[found].packets += temp.packets;
                        entries[found].bytes += temp.bytes;
                        if (temp.timestamp > entries[found].timestamp) {
                            entries[found].timestamp = temp.timestamp;
                        }
                    } else if (count < MAX_ENTRIES) {
                        entries[count] = temp;
                        count++;
                    }
                }
            }
        }
        fclose(fp);
    } else {
        fprintf(stderr, "[ALERT_MONITOR] %s 파일 열기 실패: %s\n", SESSION_LOG_FILE, strerror(errno));
        fprintf(stderr, "[ALERT_MONITOR] root 권한으로 실행 필요\n");
        free(entries);
        return;
    }
    
    // 2. Alert 정보 결합
    fp = fopen(ALERT_LOG_FILE, "r");
    if (fp) {
        char line[LINE_MAX];
        char alert_src[20], alert_dst[20], alert_msg[256];
        
        while (fgets(line, sizeof(line), fp)) {
            if (parse_alert_log(line, alert_src, alert_dst, alert_msg, sizeof(alert_msg)) == 0) {
                for (int i = 0; i < count; i++) {
                    if (strcmp(entries[i].src_ip, alert_src) == 0 ||
                        strcmp(entries[i].dst_ip, alert_dst) == 0) {
                        entries[i].has_alert = 1;
                        strncpy(entries[i].alert_msg, alert_msg, sizeof(entries[i].alert_msg) - 1);
                        break;
                    }
                }
            }
        }
        fclose(fp);
    }
    
    // 3. 스코어 계산
    for (int i = 0; i < count; i++) {
        entries[i].score = calculate_score(&entries[i]);
    }
    
    // 4. 정렬
    qsort(entries, count, sizeof(combined_entry_t), compare_score);
    
    // 5. 출력 (더블 버퍼링)
    char buffer[8192];
    int offset = 0;
    
    // 화면 클리어 및 커서 홈 이동 (ANSI Escape Code)
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\033[2J\033[1;1H");
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "║                            🛡️  MINI-IDS 실시간 위협 모니터링 (Top %d)                                        ║\n", TOP_N);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "║                                    갱신 시간: %-40s                                                        ║\n", time_str);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "║ 순위 │ 스코어  │ 출발지           │ 목적지           │ 프로토콜 │ 패킷  │ 통신량    │ Alert                      ║\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    
    int display_count = (count < TOP_N) ? count : TOP_N;
    for (int i = 0; i < display_count; i++) {
        char src_addr[30], dst_addr[30], bytes_str[20];
        snprintf(src_addr, sizeof(src_addr), "%s:%u", entries[i].src_ip, entries[i].src_port);
        snprintf(dst_addr, sizeof(dst_addr), "%s:%u", entries[i].dst_ip, entries[i].dst_port);
        format_bytes(entries[i].bytes, bytes_str, sizeof(bytes_str));
        
        char short_alert[20];
        if (entries[i].has_alert) {
            strncpy(short_alert, entries[i].alert_msg, sizeof(short_alert) - 1);
            short_alert[sizeof(short_alert) - 1] = '\0';
        } else {
            strcpy(short_alert, "-");
        }
        
        const char *color = entries[i].has_alert ? "\033[1;31m" : "\033[0m";
        const char *reset = "\033[0m";
        
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "║ %s%3d│ %7.0f  │ %-16s │ %-16s │ %-8s │ %5lu │ %-9s │ %-19s%s ║\n",
               color,
               i + 1,
               entries[i].score,
               src_addr,
               dst_addr,
               proto_to_string(entries[i].protocol),
               entries[i].packets,
               bytes_str,
               short_alert,
               reset);
    }
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    
    // 통계 요약
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    int alert_count = 0;
    
    for (int i = 0; i < count; i++) {
        total_packets += entries[i].packets;
        total_bytes += entries[i].bytes;
        if (entries[i].has_alert) alert_count++;
    }
    
    char total_bytes_str[20];
    format_bytes(total_bytes, total_bytes_str, sizeof(total_bytes_str));
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "║ 총 세션: %d개 │ Alert: %d개 │ 총 패킷: %lu │ 총 통신량: %s                                                    ║\n",
           count, alert_count, total_packets, total_bytes_str);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\n[ALERT_MONITOR] 실시간 갱신 중 (2초 간격)...\n");
    
    // 한 번에 출력
    fputs(buffer, stdout);
    fflush(stdout);
    
    free(entries);
}

// Alert Monitor 쓰레드 메인
void *alert_monitor_thread_main(void *arg) {
    (void)arg;
    
    printf("[ALERT_MONITOR] 쓰레드 시작\n");
    printf("[ALERT_MONITOR] 최근 60초 세션 모니터링\n\n");
    
    while (alert_running) {
        time_t now = time(NULL);
        time_t cutoff = now - 300;  // 최근 5분 (디버깅용)
        
        print_top_threats(cutoff);
        
        // 2초 대기 (실시간 갱신)
        for (int i = 0; i < 2 && alert_running; i++) {
            sleep(1);
        }
    }
    
    printf("[ALERT_MONITOR] 쓰레드 종료\n");
    return NULL;
}
