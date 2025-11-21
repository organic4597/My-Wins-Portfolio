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
    
    int rcvbuf = 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
        perror("setsockopt SO_RCVBUF");
        rcvbuf = 512 * 1024;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
            perror("setsockopt SO_RCVBUF (fallback)");
        }
    }
    
    unlink(UDS_SOCKET_PATH);
    
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
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("RAW socket");
        return -1;
    }
    
    int sndbuf = 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
        perror("setsockopt SO_SNDBUF (RAW)");
        sndbuf = 512 * 1024;
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
            perror("setsockopt SO_SNDBUF (RAW fallback)");
        }
    }
    
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
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("RAW socket bind");
        close(sockfd);
        return -1;
    }
    
    printf("[INJECT] RAW 소켓이 veth0에 바인드됨\n");
    return sockfd;
}

static unsigned char veth0_mac[6];
static unsigned char veth1_mac[6];

int get_iface_hwaddr(const char *ifname, unsigned char *hwaddr_out) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket for ioctl");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFHWADDR");
        close(fd);
        return -1;
    }

    memcpy(hwaddr_out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

int inject_packet_to_veth0(int sockfd, const uds_packet_t *uds_pkt) {
    struct sockaddr_ll addr;
    struct ifreq ifr;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "veth0", sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl for veth0");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    
    if (uds_pkt->packet_len >= 14) {
        memcpy((void *)uds_pkt->packet_data, veth1_mac, 6);
        memcpy((void *)(uds_pkt->packet_data + 6), veth0_mac, 6);
    }

    ssize_t sent = sendto(sockfd, uds_pkt->packet_data, uds_pkt->packet_len, 0,
                         (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent == -1) {
        if (errno == EMSGSIZE) {
            static unsigned long msg_too_long_count = 0;
            msg_too_long_count++;
            if (msg_too_long_count % 100 == 0) {
                fprintf(stderr, "[INJECT] 패킷 크기 초과: %u bytes (총 %lu개)\n", uds_pkt->packet_len, msg_too_long_count);
            }
        } else if (errno == ENOBUFS) {
            static unsigned long no_bufs_count = 0;
            no_bufs_count++;
            if (no_bufs_count % 100 == 0) {
                fprintf(stderr, "[INJECT] 버퍼 부족 (총 %lu개)\n", no_bufs_count);
            }
        } else {
            static unsigned long other_error_count = 0;
            other_error_count++;
            if (other_error_count % 100 == 0) {
                fprintf(stderr, "[INJECT] 패킷 주입 실패 (errno=%d): %s (총 %lu개)\n", errno, strerror(errno), other_error_count);
            }
        }
        return -1;
    }
    
    if (sent != (ssize_t)uds_pkt->packet_len) {
        fprintf(stderr, "[INJECT] 패킷 부분 전송: %zd / %u\n", sent, uds_pkt->packet_len);
        return -1;
    }
    
    inject_count++;
    
    if (inject_count % 100 == 0) {
        printf("[INJECT] 주입된 패킷: %lu개\n", inject_count);
    }
    
    return 0;
}

void packet_processing_loop() {
    uds_packet_t uds_pkt;
    struct sockaddr_un src_addr;
    socklen_t src_addr_len;
    
    printf("[INJECT] 패킷 수신 대기 중...\n");
    
    while (inject_running) {
        src_addr_len = sizeof(src_addr);
        
        ssize_t received = recvfrom(uds_sockfd, &uds_pkt, sizeof(uds_packet_t), 0, 
                                   (struct sockaddr*)&src_addr, &src_addr_len);
        
        if (received == -1) {
            if (errno == EINTR) {
                break;
            }
            if (errno == EMSGSIZE) {
                static unsigned long msg_too_long_count = 0;
                msg_too_long_count++;
                if (msg_too_long_count % 100 == 0) {
                    fprintf(stderr, "[INJECT] UDS 메시지 크기 초과 (총 %lu개)\n", msg_too_long_count);
                }
                continue;
            }
            perror("[INJECT] UDS recvfrom");
            break;
        }
        
        if (received > 0) {
            size_t expected_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + uds_pkt.packet_len;
            if ((size_t)received < expected_size) {
                fprintf(stderr, "[INJECT] 불완전한 패킷 수신: %zd < %zu\n", received, expected_size);
                continue;
            }
            
            if (uds_pkt.packet_len > SNAP_LEN) {
                fprintf(stderr, "[INJECT] 잘못된 패킷 크기: %u > %d\n", uds_pkt.packet_len, SNAP_LEN);
                continue;
            }
            
            inject_packet_to_veth0(raw_sockfd, &uds_pkt);
        }
    }
    
    printf("[INJECT] 패킷 수신 루프 종료\n");
}

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

    if (get_iface_hwaddr("veth0", veth0_mac) != 0) {
        fprintf(stderr, "[INJECT] veth0 MAC 주소 가져오기 실패\n");
    } else {
        printf("[INJECT] veth0 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               veth0_mac[0], veth0_mac[1], veth0_mac[2], veth0_mac[3], veth0_mac[4], veth0_mac[5]);
    }
    if (get_iface_hwaddr("veth1", veth1_mac) != 0) {
        fprintf(stderr, "[INJECT] veth1 MAC 주소 가져오기 실패\n");
    } else {
        printf("[INJECT] veth1 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               veth1_mac[0], veth1_mac[1], veth1_mac[2], veth1_mac[3], veth1_mac[4], veth1_mac[5]);
    }

    packet_processing_loop();
    cleanup_inject();
    
    return (void *)0;
}