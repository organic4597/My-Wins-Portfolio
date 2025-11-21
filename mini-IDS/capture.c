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
    
    int sndbuf = 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
        perror("setsockopt SO_SNDBUF");
        sndbuf = 512 * 1024;
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
            perror("setsockopt SO_SNDBUF (fallback)");
        }
    }
    
    return sockfd;
}

// UDS 패킷 전송
int send_to_inject(int sockfd, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct sockaddr_un addr;
    uds_packet_t uds_pkt;
    
    if (pkthdr->caplen > SNAP_LEN) {
        fprintf(stderr, "[CAPTURE] 캡처된 패킷 크기 초과: %u > %d\n", pkthdr->caplen, SNAP_LEN);
        return -1;
    }
    
    const size_t MAX_UDS_PACKET_SIZE = 204800;
    if (pkthdr->caplen > MAX_UDS_PACKET_SIZE) {
        static unsigned long skip_count = 0;
        skip_count++;
        if (skip_count % 100 == 0) {
            fprintf(stderr, "[CAPTURE] 매우 큰 패킷 건너뛰기: %u bytes (총 %lu개)\n", pkthdr->caplen, skip_count);
        }
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UDS_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    uds_pkt.packet_len = (uint32_t)pkthdr->caplen;
    uds_pkt.timestamp_sec = pkthdr->ts.tv_sec;
    uds_pkt.timestamp_usec = pkthdr->ts.tv_usec;
    memcpy(uds_pkt.packet_data, packet, pkthdr->caplen);
    
    size_t send_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + uds_pkt.packet_len;
    ssize_t sent = sendto(sockfd, &uds_pkt, send_size, 0,
                         (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent == -1) {
        if (errno == EMSGSIZE) {
            static unsigned long msg_too_long_count = 0;
            msg_too_long_count++;
            if (msg_too_long_count % 100 == 0) {
                fprintf(stderr, "[CAPTURE] UDS 메시지 크기 초과: %u bytes (총 %lu개)\n", pkthdr->caplen, msg_too_long_count);
            }
        } else {
            perror("[CAPTURE] sendto");
        }
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
    
    if (packet_count % 100 == 0) {
        printf("[CAPTURE] 캡처된 패킷: %lu개\n", packet_count);
    }
    
    if (uds_socket != -1) {
        if (send_to_inject(uds_socket, pkthdr, packet) != 0) {
            fprintf(stderr, "[CAPTURE] UDS 전송 실패\n");
        }
    }
}

int init_capture(char *dev_name, pcap_t **handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (dev_name == NULL || strcmp(dev_name, "none") == 0) {
        dev_name = "eth0";
    }

    printf("[CAPTURE] 디바이스: %s\n", dev_name);
    fflush(stdout);
    
    *handle = pcap_open_live(dev_name, SNAP_LEN, 1, 1000, errbuf);
    if (*handle == NULL) {
        fprintf(stderr, "[CAPTURE] Couldn't open device %s: %s\n", dev_name, errbuf);
        fflush(stderr);
        return -1;
    }

    int dlt = pcap_datalink(*handle);
    printf("[CAPTURE] Datalink type: %s (%d)\n", pcap_datalink_val_to_name(dlt), dlt);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "[CAPTURE] Warning: Non-Ethernet datalink type detected\n");
    }

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[CAPTURE] Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
        net = 0;
        mask = 0;
    }
    
    char filter_exp[] = "tcp or udp or icmp or icmp6";
    
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

void *capture_thread_main(void *arg) {
    pcap_t *handle = NULL;
    char *dev_name = (char *)arg;
    
    printf("[CAPTURE] 스레드 시작\n");
    fflush(stdout);
    
    if (dev_name == NULL) {
        dev_name = "eth0";
    }
    
    uds_socket = create_uds_sender();
    if (uds_socket == -1) {
        fprintf(stderr, "[CAPTURE] UDS 소켓 생성 실패\n");
        fflush(stderr);
        return (void *)-1;
    }
    printf("[CAPTURE] UDS 소켓 생성 완료\n");
    fflush(stdout);
    
    if (init_capture(dev_name, &handle) != 0) {
        fprintf(stderr, "[CAPTURE] init_capture 실패\n");
        fflush(stderr);
        close(uds_socket);
        uds_socket = -1;
        return (void *)-1;
    }
    
    printf("[CAPTURE] 패킷 캡처 시작\n");
    fflush(stdout);
    start_capture(handle);
    
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