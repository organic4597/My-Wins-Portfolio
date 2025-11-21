#include "common.h"
#include "veth_manager.h"
#include "alert_monitor.h"

// extern 선언
extern void *capture_thread_main(void *arg);
extern void *inject_thread_main(void *arg);
extern volatile sig_atomic_t capture_running;
extern volatile sig_atomic_t inject_running;

static volatile sig_atomic_t main_running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    printf("\n[MAIN] SIGINT 수신, 정리 중...\n");
    main_running = 0;
    alert_running = 0;
}

int main(int argc, char *argv[])
{
    pthread_t cap_thread, inj_thread, alert_thread;
    char *dev_name = "none";
    void *cap_ret, *inj_ret, *alert_ret;
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    if (argc > 1) {
        dev_name = argv[1];
    }
    
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("[MAIN] mini-IDS 시작 (디바이스: %s)\n", dev_name);
    fflush(stdout);
    
    printf("[MAIN] veth 인터페이스 확인 중...\n");
    if (check_veth_exists("veth0") && check_veth_exists("veth1")) {
        printf("[MAIN] veth0/veth1이 이미 존재함, 재사용합니다\n");
    } else {
        printf("[MAIN] veth 쌍 생성 시도 중...\n");
        if (create_veth_pair("veth0", "veth1", 9000) != 0) {
            fprintf(stderr, "[MAIN] veth 생성 실패\n");
            
            if (check_veth_exists("veth0") && check_veth_exists("veth1")) {
                printf("[MAIN] 기존 veth0/veth1을 사용합니다\n");
            } else {
                fprintf(stderr, "[MAIN] veth 인터페이스가 없습니다.\n");
                fprintf(stderr, "[MAIN] 수동 생성: sudo ip link add veth0 type veth peer name veth1\n");
                fprintf(stderr, "[MAIN] 또는 start_mini_ids.sh 스크립트를 사용하세요\n");
                return 1;
            }
        } else {
            printf("[MAIN] veth 쌍 생성 완료: veth0 <-> veth1\n");
        }
    }
    sleep(1);
    
    if (pthread_create(&inj_thread, NULL, inject_thread_main, NULL) != 0) {
        perror("[MAIN] pthread_create inject");
        return 1;
    }
    printf("[MAIN] inject 스레드 생성 완료\n");
    
    sleep(1);
    
    if (pthread_create(&cap_thread, NULL, capture_thread_main, dev_name) != 0) {
        perror("[MAIN] pthread_create capture");
        fflush(stderr);
        inject_running = 0;
        pthread_join(inj_thread, NULL);
        return 1;
    }
    printf("[MAIN] capture 스레드 생성 완료\n");
    fflush(stdout);
    
    if (pthread_create(&alert_thread, NULL, alert_monitor_thread_main, NULL) != 0) {
        perror("[MAIN] pthread_create alert_monitor");
        alert_thread = 0;
    } else {
        printf("[MAIN] alert_monitor 스레드 생성 완료\n");
    }
    
    printf("[MAIN] 모든 스레드 실행 중... (Ctrl+C로 종료)\n");
    
    while (main_running) {
        sleep(1);
    }
    
    printf("[MAIN] 스레드 종료 신호 전송 중...\n");
    capture_running = 0;
    inject_running = 0;
    alert_running = 0;
    
    pthread_join(cap_thread, &cap_ret);
    printf("[MAIN] capture 스레드 종료: %p\n", cap_ret);
    
    pthread_join(inj_thread, &inj_ret);
    printf("[MAIN] inject 스레드 종료: %p\n", inj_ret);
    
    if (alert_thread) {
        pthread_join(alert_thread, &alert_ret);
        printf("[MAIN] alert_monitor 스레드 종료: %p\n", alert_ret);
    }
    
    printf("[MAIN] veth 정리 중...\n");
    delete_veth("veth0");
    
    printf("[MAIN] mini-IDS 종료 완료\n");
    return 0;
}