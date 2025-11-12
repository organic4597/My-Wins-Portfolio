#include "common.h"

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
}

int main(int argc, char *argv[])
{
    pthread_t cap_thread, inj_thread;
    char *dev_name = "eth0";
    void *cap_ret, *inj_ret;
    
    if (argc > 1) {
        dev_name = argv[1];
    }
    
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("[MAIN] mini-IDS 시작 (디바이스: %s)\n", dev_name);
    printf("[MAIN] root 권한 필요\n");
    
    // inject 스레드 먼저 시작 (UDS 서버 대기)
    if (pthread_create(&inj_thread, NULL, inject_thread_main, NULL) != 0) {
        perror("[MAIN] pthread_create inject");
        return 1;
    }
    printf("[MAIN] inject 스레드 생성 완료\n");
    
    // inject 스레드가 준비될 때까지 대기
    sleep(1);
    
    // capture 스레드 시작
    if (pthread_create(&cap_thread, NULL, capture_thread_main, dev_name) != 0) {
        perror("[MAIN] pthread_create capture");
        inject_running = 0;
        pthread_join(inj_thread, NULL);
        return 1;
    }
    printf("[MAIN] capture 스레드 생성 완료\n");
    
    printf("[MAIN] 두 스레드 모두 실행 중... (Ctrl+C로 종료)\n");
    
    // 메인 스레드는 시그널 대기
    while (main_running) {
        sleep(1);
    }
    
    // 스레드 종료 신호
    printf("[MAIN] 스레드 종료 신호 전송 중...\n");
    capture_running = 0;
    inject_running = 0;
    
    // 스레드 종료 대기
    pthread_join(cap_thread, &cap_ret);
    printf("[MAIN] capture 스레드 종료: %p\n", cap_ret);
    
    pthread_join(inj_thread, &inj_ret);
    printf("[MAIN] inject 스레드 종료: %p\n", inj_ret);
    
    printf("[MAIN] mini-IDS 종료 완료\n");
    return 0;
}