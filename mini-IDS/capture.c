#include "common.h"

// 전역 변수
int uds_socket = -1;
unsigned long packet_count = 0;
volatile sig_atomic_t capture_running = 1;

// UDS 클라이언트 생성
int create_uds_sender() {
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }
    return sockfd;
}

// UDS 패킷 전송
int send_to_inject(int sockfd, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct sockaddr_un addr;
    uds_packet_t uds_pkt;
    
    if (pkthdr->len > SNAP_LEN) {
        fprintf(stderr, "[CAPTURE] 패킷 크기 초과: %u > %d\n", pkthdr->len, SNAP_LEN);
        return -1;
    }
    
    // UDS 주소 설정
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UDS_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    // UDS 패킷 구성
    uds_pkt.packet_len = pkthdr->len;
    uds_pkt.timestamp_sec = pkthdr->ts.tv_sec;
    uds_pkt.timestamp_usec = pkthdr->ts.tv_usec;
    memcpy(uds_pkt.packet_data, packet, pkthdr->len);
    
    // 전송
    size_t send_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + pkthdr->len;
    ssize_t sent = sendto(sockfd, &uds_pkt, send_size, 0,
                         (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent == -1) {
        perror("[CAPTURE] sendto");
        return -1;
    }
    
    return 0;
}

// 패킷 핸들러
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    (void)user;
    
    if (!capture_running) {
        return;
    }
    
    packet_count++;
    
    // 100개마다 진행 상황 출력
    if (packet_count % 100 == 0) {
        printf("[CAPTURE] 캡처된 패킷: %lu개\n", packet_count);
    }
    
    // UDS로 패킷 전송
    if (uds_socket != -1) {
        if (send_to_inject(uds_socket, pkthdr, packet) != 0) {
            fprintf(stderr, "[CAPTURE] UDS 전송 실패\n");
        }
    }
}

int init_capture(char *dev_name, pcap_t **handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (dev_name == NULL) {
        dev_name = "eth0";
    }

    printf("[CAPTURE] 디바이스: %s\n", dev_name);
    
    *handle = pcap_open_live(dev_name, SNAP_LEN, 1, 1000, errbuf);
    if (*handle == NULL) {
        fprintf(stderr, "[CAPTURE] Couldn't open device %s: %s\n", dev_name, errbuf);
        return -1;
    }

    // BPF 필터 설정
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[CAPTURE] Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
        net = 0;
        mask = 0;
    }
    
    // 필터 표현식 (모든 TCP, UDP, ICMP)
    char filter_exp[] = "tcp or udp or icmp";
    
    if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "[CAPTURE] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(*handle));
        return -1;
    }
    
    if (pcap_setfilter(*handle, &fp) == -1) {
        fprintf(stderr, "[CAPTURE] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(*handle));
        pcap_freecode(&fp);
        return -1;
    }
    
    pcap_freecode(&fp);
    printf("[CAPTURE] BPF 필터 적용: %s\n", filter_exp);
    return 0;
}

int start_capture(pcap_t *handle)
{
    int ret = pcap_loop(handle, 0, packet_handler, NULL);
    if (ret == -1) {
        fprintf(stderr, "[CAPTURE] Error in pcap_loop\n");
        return -1;
    }
    return 0;
}

// capture 스레드 진입점
void *capture_thread_main(void *arg) {
    pcap_t *handle = NULL;
    char *dev_name = (char *)arg;
    
    if (dev_name == NULL) {
        dev_name = "eth0";
    }
    
    // UDS 송신 소켓 생성
    uds_socket = create_uds_sender();
    if (uds_socket == -1) {
        fprintf(stderr, "[CAPTURE] UDS 소켓 생성 실패\n");
        return (void *)-1;
    }
    printf("[CAPTURE] UDS 소켓 생성 완료\n");
    
    if (init_capture(dev_name, &handle) != 0) {
        close(uds_socket);
        uds_socket = -1;
        return (void *)-1;
    }
    
    printf("[CAPTURE] 패킷 캡처 시작\n");
    start_capture(handle);
    
    // 정리
    printf("\n[CAPTURE] 총 %lu개 패킷 캡처 완료\n", packet_count);
    if (uds_socket != -1) {
        close(uds_socket);
        uds_socket = -1;
    }
    if (handle != NULL) {
        pcap_close(handle);
    }
    
    return (void *)0;
}