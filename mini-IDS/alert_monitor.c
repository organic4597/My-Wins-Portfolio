#include "alert_monitor.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

volatile sig_atomic_t alert_running = 1;

static const char* get_app_protocol(int proto, int src_port, int dst_port) {
    if (proto == 1) return "ICMP";
    if (proto == 6) {
        if (src_port == 80 || dst_port == 80) return "HTTP";
        if (src_port == 443 || dst_port == 443) return "HTTPS";
        if (src_port == 22 || dst_port == 22) return "SSH";
        if (src_port == 21 || dst_port == 21) return "FTP";
        if (src_port == 23 || dst_port == 23) return "TELNET";
        if (src_port == 25 || dst_port == 25) return "SMTP";
        return "TCP";
    }
    if (proto == 17) {
        if (src_port == 53 || dst_port == 53) return "DNS";
        if (src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68) return "DHCP";
        if (src_port == 123 || dst_port == 123) return "NTP";
        return "UDP";
    }
    return "OTHER";
}

static int parse_session_log(const char *line, combined_entry_t *entry) {
    char mutable_line[LINE_MAX];
    strncpy(mutable_line, line, sizeof(mutable_line));
    mutable_line[sizeof(mutable_line) - 1] = '\0';

    char *saveptr;
    char *token;
    const char *delim = "|";
    
    token = strtok_r(mutable_line, delim, &saveptr);
    if (!token) return -1;
    entry->timestamp = atol(token);
    
    token = strtok_r(NULL, delim, &saveptr);
    if (!token) return -1;
    char *colon = strrchr(token, ':');
    if (colon) {
        *colon = '\0';
        strncpy(entry->src_ip, token, sizeof(entry->src_ip) - 1);
        entry->src_port = atoi(colon + 1);
    } else {
        strncpy(entry->src_ip, token, sizeof(entry->src_ip) - 1);
        entry->src_port = 0;
    }
    entry->src_ip[sizeof(entry->src_ip) - 1] = '\0';

    token = strtok_r(NULL, delim, &saveptr);
    if (!token) return -1;
    colon = strrchr(token, ':');
    if (colon) {
        *colon = '\0';
        strncpy(entry->dst_ip, token, sizeof(entry->dst_ip) - 1);
        entry->dst_port = atoi(colon + 1);
    } else {
        strncpy(entry->dst_ip, token, sizeof(entry->dst_ip) - 1);
        entry->dst_port = 0;
    }
    entry->dst_ip[sizeof(entry->dst_ip) - 1] = '\0';

    token = strtok_r(NULL, delim, &saveptr);
    if (!token) return -1;
    entry->protocol = (unsigned char)atoi(token);

    token = strtok_r(NULL, delim, &saveptr);
    if (!token) return -1;
    entry->packets = strtoul(token, NULL, 10);

    token = strtok_r(NULL, delim, &saveptr);
    if (!token) return -1;
    entry->bytes = strtoul(token, NULL, 10);

    entry->has_alert = 0;
    entry->alert_msg[0] = '\0';
    
    return 0;
}

static int parse_alert_log(const char *line, char *src_ip, char *dst_ip, int *out_proto, char *alert_msg, size_t msg_size) {
    char *msg_start = strstr(line, "] \"");
    if (msg_start) {
        msg_start += 3;
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
    
    *out_proto = -1;
    char *proto_start = strchr(line, '{');
    if (proto_start) {
        char *proto_end = strchr(proto_start, '}');
        if (proto_end && proto_end > proto_start + 1) {
            size_t plen = proto_end - proto_start - 1;
            char proto_str[32];
            if (plen >= sizeof(proto_str)) plen = sizeof(proto_str) - 1;
            strncpy(proto_str, proto_start + 1, plen);
            proto_str[plen] = '\0';

            if (strstr(proto_str, "TCP") != NULL) *out_proto = 6;
            else if (strstr(proto_str, "UDP") != NULL) *out_proto = 17;
            else if (strstr(proto_str, "ICMP") != NULL) *out_proto = 1;
        }
    }

    if (proto_start) {
        char *arrow = strstr(proto_start, " -> ");
        if (arrow) {
            char *src_start = proto_start;
            while (*src_start && !isdigit(*src_start) && *src_start != '[') src_start++;

            if (src_start && *src_start) {
                char *src_end = arrow;
                while (src_end > src_start && isspace(*(src_end - 1))) src_end--;
                
                size_t src_len = src_end - src_start;
                if (src_len >= 128) src_len = 127;
                
                char src_full[128];
                strncpy(src_full, src_start, src_len);
                src_full[src_len] = '\0';

                if (*out_proto == 1) {
                    strncpy(src_ip, src_full, 63);
                    src_ip[63] = '\0';
                } else {
                    char *colon = strchr(src_full, ':');
                    if (colon) {
                        char *last_colon = strrchr(src_full, ':');
                        if (last_colon && strchr(last_colon + 1, ':') == NULL) {
                            *last_colon = '\0';
                        }
                    }
                    strncpy(src_ip, src_full, 63);
                    src_ip[63] = '\0';
                }

                char *dst_start = arrow + 4;
                while (*dst_start && isspace(*dst_start)) dst_start++;
                
                if (*dst_start) {
                    char *dst_end = dst_start;
                    while (*dst_end && !isspace(*dst_end) && *dst_end != '\n' && *dst_end != '\r') dst_end++;
                    
                    size_t dst_len = dst_end - dst_start;
                    if (dst_len >= 128) dst_len = 127;
                    
                    char dst_full[128];
                    strncpy(dst_full, dst_start, dst_len);
                    dst_full[dst_len] = '\0';

                    if (*out_proto == 1) {
                        strncpy(dst_ip, dst_full, 63);
                        dst_ip[63] = '\0';
                    } else {
                        char *colon = strchr(dst_full, ':');
                        if (colon) {
                            char *last_colon = strrchr(dst_full, ':');
                            if (last_colon && strchr(last_colon + 1, ':') == NULL) {
                                *last_colon = '\0';
                            }
                        }
                        strncpy(dst_ip, dst_full, 63);
                        dst_ip[63] = '\0';
                    }

                    return 0;
                }
            }
        }
    }
    
    return -1;
}

static double calculate_score(const combined_entry_t *entry) {
    double score = 0.0;
    
    if (entry->has_alert) {
        score += 1000.0;
        if (entry->protocol == 1 || entry->protocol == 58) {
            score += 500.0;
        }
    }
    
    if (entry->protocol == 1 || entry->protocol == 58) {
        score += 500.0;
    } else if (entry->protocol == 17) {
        score += 200.0;
    }
    
    score += entry->packets * 10.0;
    score += (entry->bytes / 1024.0);
    
    return score;
}

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

static int compare_score(const void *a, const void *b) {
    const combined_entry_t *ea = (const combined_entry_t *)a;
    const combined_entry_t *eb = (const combined_entry_t *)b;
    
    if (eb->score > ea->score) return 1;
    if (eb->score < ea->score) return -1;
    return 0;
}

static void print_top_threats(time_t cutoff_time) {
    combined_entry_t *entries = malloc(sizeof(combined_entry_t) * MAX_ENTRIES);
    if (!entries) {
        fprintf(stderr, "[ALERT_MONITOR] 메모리 할당 실패\n");
        return;
    }
    
    int count = 0;
    
    FILE *fp = fopen(SESSION_LOG_FILE, "r");
    if (fp) {
        char line[LINE_MAX];
        combined_entry_t temp;
        while (fgets(line, sizeof(line), fp)) {
            if (parse_session_log(line, &temp) == 0) {
                if (temp.timestamp >= cutoff_time) {
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
        free(entries);
        return;
    }
    
    fp = fopen(ALERT_LOG_FILE, "r");
    if (fp) {
        char line[LINE_MAX];
        char alert_src[64], alert_dst[64], alert_msg[256];
        int alert_proto;

        while (fgets(line, sizeof(line), fp)) {
            if (parse_alert_log(line, alert_src, alert_dst, &alert_proto, alert_msg, sizeof(alert_msg)) == 0) {
                for (int i = 0; i < count; i++) {
                    int matched = 0;

                    if ((strcmp(entries[i].src_ip, alert_src) == 0 && strcmp(entries[i].dst_ip, alert_dst) == 0) ||
                        (strcmp(entries[i].src_ip, alert_dst) == 0 && strcmp(entries[i].dst_ip, alert_src) == 0)) {
                        if (alert_proto != -1) {
                            if (entries[i].protocol == alert_proto) matched = 1;
                        } else {
                            matched = 1;
                        }
                    }

                    if (matched) {
                        entries[i].has_alert = 1;
                        strncpy(entries[i].alert_msg, alert_msg, sizeof(entries[i].alert_msg) - 1);
                        entries[i].alert_msg[sizeof(entries[i].alert_msg) - 1] = '\0';
                        break;
                    }
                }
            }
        }
        fclose(fp);
    }
    
    for (int i = 0; i < count; i++) {
        entries[i].score = calculate_score(&entries[i]);
    }
    
    qsort(entries, count, sizeof(combined_entry_t), compare_score);
    
    char buffer[8192];
    int offset = 0;
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\033[2J\033[1;1H");
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "                            🛡️  MINI-IDS 실시간 위협 모니터링 (Top %d)                                        \n", TOP_N);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "                                    갱신 시간: %-40s                                                        \n", time_str);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " 순위 │ 스코어  │ 출발지           │ 목적지           │ 프로토콜 │ 패킷  │ 통신량    │ Alert                      \n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    int display_count = (count < TOP_N) ? count : TOP_N;
    for (int i = 0; i < display_count; i++) {
        char src_addr[128], dst_addr[128], bytes_str[20];
        if (entries[i].protocol == 1) {
            snprintf(src_addr, sizeof(src_addr), "%s", entries[i].src_ip);
            snprintf(dst_addr, sizeof(dst_addr), "%s", entries[i].dst_ip);
        } else {
            snprintf(src_addr, sizeof(src_addr), "%s:%u", entries[i].src_ip, entries[i].src_port);
            snprintf(dst_addr, sizeof(dst_addr), "%s:%u", entries[i].dst_ip, entries[i].dst_port);
        }
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
        
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, " %s%3d│ %7.0f  │ %-16s │ %-16s │ %-8s │ %5lu │ %-9s │ %-19s%s \n",
               color,
               i + 1,
               entries[i].score,
               src_addr,
               dst_addr,
               get_app_protocol(entries[i].protocol, entries[i].src_port, entries[i].dst_port),
               entries[i].packets,
               bytes_str,
               short_alert,
               reset);
    }
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
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
    
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " 총 세션: %d개 │ Alert: %d개 │ 총 패킷: %lu │ 총 통신량: %s                                                    \n",
           count, alert_count, total_packets, total_bytes_str);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\n[ALERT_MONITOR] 실시간 갱신 중 (2초 간격)...\n");
    
    fputs(buffer, stdout);
    fflush(stdout);
    
    free(entries);
}

void *alert_monitor_thread_main(void *arg) {
    (void)arg;
    
    printf("[ALERT_MONITOR] 쓰레드 시작\n");
    printf("[ALERT_MONITOR] 최근 60초 세션 모니터링\n\n");
    
    while (alert_running) {
        time_t now = time(NULL);
        time_t cutoff = now - 60;
        
        print_top_threats(cutoff);
        
        for (int i = 0; i < 2 && alert_running; i++) {
            sleep(1);
        }
    }
    
    printf("[ALERT_MONITOR] 쓰레드 종료\n");
    return NULL;
}
