#include "common.h"

// inject 전용 변수
int uds_sockfd = -1;
int raw_sockfd = -1;
unsigned long inject_count = 0;
volatile sig_atomic_t inject_running = 1;

//UDS 리시버 생성
int create_uds_receiver() {
    int sockfd;
    struct sockaddr_un addr;

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("UDS socket");
        return -1;
    }
    
    unlink(UDS_SOCKET_PATH); // 기존 소켓 파일 제거
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UDS_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("UDS bind");
        close(sockfd);
        return -1;
    }
    
    printf("[INJECT] UDS 서버 생성 완료: %s\n", UDS_SOCKET_PATH);
    return sockfd;
}

int create_raw_socket() {
    int sockfd;
    struct sockaddr_ll addr;
    struct ifreq ifr;
    
    // RAW 소켓 생성
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("RAW socket");
        return -1;
    }
    
    // veth0 인터페이스 정보 가져오기
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "veth0", sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    
    // 소켓을 veth0에 바인드
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("RAW socket bind");
        close(sockfd);
        return -1;
    }
    
    printf("[INJECT] RAW 소켓이 veth0에 바인드됨\n");
    return sockfd;
}

// 패킷을 veth0으로 주입
int inject_packet_to_veth0(int sockfd, const uds_packet_t *uds_pkt) {
    struct sockaddr_ll addr;
    struct ifreq ifr;
    
    // veth0 인터페이스 정보
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "veth0", sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl for veth0");
        return -1;
    }
    
    // 주소 설정
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    
    // 패킷 주입
    ssize_t sent = sendto(sockfd, uds_pkt->packet_data, uds_pkt->packet_len, 0,
                         (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent == -1) {
        perror("[INJECT] 패킷 주입 실패");
        return -1;
    }
    
    if (sent != (ssize_t)uds_pkt->packet_len) {
        fprintf(stderr, "[INJECT] 패킷 부분 전송: %zd / %u\n", sent, uds_pkt->packet_len);
        return -1;
    }
    
    inject_count++;
    
    // 100개마다 진행 상황 출력
    if (inject_count % 100 == 0) {
        printf("[INJECT] 주입된 패킷: %lu개\n", inject_count);
    }
    
    return 0;
}

// 패킷 처리 루프
void packet_processing_loop() {
    uds_packet_t uds_pkt;
    struct sockaddr_un src_addr;
    socklen_t src_addr_len;
    
    printf("[INJECT] 패킷 수신 대기 중...\n");
    
    while (inject_running) {
        src_addr_len = sizeof(src_addr);
        
        // UDS에서 패킷 수신 (블로킹)
        ssize_t received = recvfrom(uds_sockfd, &uds_pkt, sizeof(uds_packet_t), 0, 
                                   (struct sockaddr*)&src_addr, &src_addr_len);
        
        if (received == -1) {
            if (errno == EINTR) {
                // 시그널로 인한 중단
                break;
            }
            perror("[INJECT] UDS recvfrom");
            break;
        }
        
        if (received > 0) {
            // veth0으로 패킷 주입
            if (inject_packet_to_veth0(raw_sockfd, &uds_pkt) != 0) {
                fprintf(stderr, "[INJECT] 패킷 주입 실패\n");
            }
        }
    }
    
    printf("[INJECT] 패킷 수신 루프 종료\n");
}

// 정리 함수
void cleanup_inject() {
    if (uds_sockfd != -1) {
        close(uds_sockfd);
        unlink(UDS_SOCKET_PATH);
        uds_sockfd = -1;
    }
    if (raw_sockfd != -1) {
        close(raw_sockfd);
        raw_sockfd = -1;
    }
    printf("\n[INJECT] 총 %lu개 패킷 주입 완료\n", inject_count);
    printf("[INJECT] 정리 완료\n");
}

// inject 스레드 진입점
void *inject_thread_main(void *arg) {
    (void)arg;
    
    uds_sockfd = create_uds_receiver();
    if (uds_sockfd == -1) {
        fprintf(stderr, "[INJECT] UDS 리시버 생성 실패\n");
        return (void *)-1;
    }

    raw_sockfd = create_raw_socket();
    if (raw_sockfd == -1) {
        fprintf(stderr, "[INJECT] RAW 소켓 생성 실패\n");
        cleanup_inject();
        return (void *)-1;
    }

    packet_processing_loop();
    cleanup_inject();
    
    return (void *)0;
}