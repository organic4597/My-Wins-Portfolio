# Mini-IDS 아키텍처 문서

## 📋 목차
1. [프로젝트 개요](#프로젝트-개요)
2. [파일별 역할 및 함수](#파일별-역할-및-함수)
3. [전체 시스템 흐름도](#전체-시스템-흐름도)
4. [데이터 흐름](#데이터-흐름)

---

## 프로젝트 개요

Mini-IDS는 네트워크 패킷을 캡처하여 Snort3로 전달하고, 탐지 결과를 실시간으로 모니터링하는 침입 탐지 시스템입니다.

**주요 구성 요소:**
- 패킷 캡처 (libpcap)
- 패킷 주입 (Raw Socket)
- Snort3 통합
- 실시간 위협 모니터링

---

## 파일별 역할 및 함수

### 1. `main.c` - 메인 프로그램 진입점

**역할:** 프로그램 초기화, 스레드 관리, 시그널 처리

**주요 함수:**
- `main(int argc, char *argv[])`
  - 프로그램 진입점
  - veth 쌍 생성/확인
  - 3개 스레드 생성 (capture, inject, alert_monitor)
  - 시그널 처리 및 정리

- `sigint_handler(int sig)`
  - SIGINT/SIGTERM 시그널 처리
  - 모든 스레드 종료 신호 전송

**의존성:**
- `veth_manager.h` - veth 인터페이스 관리
- `alert_monitor.h` - Alert Monitor 스레드
- `capture.c` - 패킷 캡처 스레드
- `inject.c` - 패킷 주입 스레드

---

### 2. `capture.c` - 패킷 캡처 모듈

**역할:** 네트워크 인터페이스에서 패킷을 캡처하고 UDS로 전송

**주요 함수:**
- `create_uds_sender()`
  - UDS DGRAM 소켓 생성 (송신용)
  - 소켓 버퍼 크기 설정 (1MB, fallback 512KB)

- `send_to_inject(int sockfd, const struct pcap_pkthdr *pkthdr, const u_char *packet)`
  - 패킷을 UDS 패킷 구조체로 변환
  - UDS를 통해 inject 스레드로 전송
  - 큰 패킷(>200KB) 필터링

- `packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)`
  - libpcap 콜백 함수
  - 캡처된 패킷을 처리하여 UDS로 전송

- `init_capture(char *dev_name, pcap_t **handle)`
  - libpcap 핸들 초기화
  - BPF 필터 설정 (tcp or udp or icmp or icmp6)
  - 네트워크 인터페이스 설정

- `start_capture(pcap_t *handle)`
  - 패킷 캡처 루프 시작

- `capture_thread_main(void *arg)`
  - 캡처 스레드 진입점
  - UDS 소켓 생성 및 패킷 캡처 시작

**전역 변수:**
- `uds_socket` - UDS 송신 소켓
- `packet_count` - 캡처된 패킷 수
- `capture_running` - 스레드 실행 플래그

---

### 3. `inject.c` - 패킷 주입 모듈

**역할:** UDS에서 패킷을 수신하여 veth0 인터페이스로 주입

**주요 함수:**
- `create_uds_receiver()`
  - UDS DGRAM 소켓 생성 (수신용)
  - 소켓 버퍼 크기 설정 (1MB, fallback 512KB)
  - UDS 서버 바인드

- `create_raw_socket()`
  - RAW 소켓 생성 (AF_PACKET)
  - 소켓 버퍼 크기 설정 (1MB, fallback 512KB)
  - veth0 인터페이스에 바인드

- `get_iface_hwaddr(const char *ifname, unsigned char *hwaddr_out)`
  - 인터페이스의 MAC 주소 조회

- `inject_packet_to_veth0(int sockfd, const uds_packet_t *uds_pkt)`
  - 패킷을 veth0으로 주입
  - MAC 주소 재작성 (veth0/veth1 MAC으로 변경)
  - RAW 소켓을 통해 패킷 전송

- `packet_processing_loop()`
  - UDS에서 패킷 수신 루프
  - 패킷 검증 및 주입

- `cleanup_inject()`
  - 리소스 정리 (소켓 닫기)

- `inject_thread_main(void *arg)`
  - 주입 스레드 진입점
  - UDS 서버 및 RAW 소켓 생성
  - 패킷 처리 루프 시작

**전역 변수:**
- `uds_sockfd` - UDS 수신 소켓
- `raw_sockfd` - RAW 소켓
- `inject_count` - 주입된 패킷 수
- `inject_running` - 스레드 실행 플래그

---

### 4. `veth_manager.c` - 가상 이더넷 인터페이스 관리

**역할:** veth 쌍 생성, 삭제, 상태 확인

**주요 함수:**
- `create_veth_pair(const char *name1, const char *name2, int mtu)`
  - veth 쌍 생성 (name1 <-> name2)
  - MTU 설정 (기본 9000)
  - Netlink API 사용

- `set_link_up(struct nl_sock *sock, const char *name)`
  - 인터페이스를 UP 상태로 설정

- `delete_veth(const char *name)`
  - veth 인터페이스 삭제

- `check_veth_exists(const char *name)`
  - veth 인터페이스 존재 여부 확인

**의존성:**
- libnl-3, libnl-route-3 (Netlink 라이브러리)

---

### 5. `alert_monitor.c` - 실시간 위협 모니터링

**역할:** Snort Alert와 세션 통계를 결합하여 실시간 위협 대시보드 표시

**주요 함수:**
- `get_app_protocol(int proto, int src_port, int dst_port)`
  - 프로토콜 번호와 포트를 기반으로 애플리케이션 프로토콜 이름 반환
  - 예: TCP 443 → HTTPS, UDP 53 → DNS

- `parse_session_log(const char *line, combined_entry_t *entry)`
  - 세션 로그 파일 파싱
  - 형식: `timestamp|src_ip:port|dst_ip:port|protocol|packets|bytes`
  - ICMP는 포트가 없음

- `parse_alert_log(const char *line, char *src_ip, char *dst_ip, int *out_proto, char *alert_msg, size_t msg_size)`
  - Snort Alert 로그 파싱
  - 형식: `[**] [sid:rev] "message" [**] {PROTO} src -> dst`

- `calculate_score(const combined_entry_t *entry)`
  - 위협 스코어 계산
  - Alert 있음: +1000점
  - ICMP/ICMPv6: +500점 보너스
  - UDP: +200점 보너스
  - 패킷 수 × 10점
  - 바이트 수 / 1024점

- `format_bytes(uint64_t bytes, char *buf, size_t bufsize)`
  - 바이트 수를 읽기 쉬운 형식으로 변환 (B, KB, MB, GB)

- `compare_score(const void *a, const void *b)`
  - qsort 비교 함수 (스코어 내림차순)

- `print_top_threats(time_t cutoff_time)`
  - 최근 60초 세션 중 Top 10 위협 표시
  - 세션 로그와 Alert 로그 결합
  - 스코어 계산 및 정렬
  - 대시보드 출력

- `alert_monitor_thread_main(void *arg)`
  - Alert Monitor 스레드 진입점
  - 2초마다 대시보드 갱신

**전역 변수:**
- `alert_running` - 스레드 실행 플래그

**파일 경로:**
- `/tmp/session_stats.log` - 세션 통계 로그
- `/tmp/alert_fast.txt` - Snort Alert 로그

---

### 6. `session_stats_inspector.cc` - Snort3 플러그인

**역할:** Snort3에서 패킷을 분석하여 세션 통계 수집 및 로그 기록

**주요 클래스:**
- `SessionStatsModule` - Snort 모듈
- `SessionStatsInspector` - 패킷 인스펙터

**주요 함수:**
- `SessionStatsInspector::eval(Packet* p)`
  - 패킷 분석 콜백
  - IP 주소, 프로토콜, 포트 추출
  - 세션 맵에 통계 누적
  - 1초마다 flush

- `SessionStatsInspector::flush_stats()`
  - 세션 통계를 파일에 기록
  - 형식: `timestamp|src_ip:port|dst_ip:port|protocol|packets|bytes`
  - ICMP/ICMPv6는 포트 없음

**플러그인 API:**
- `PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__ICMP` - 지원 프로토콜
- `IT_PACKET` - 패킷 레벨 인스펙터

**파일 경로:**
- `/tmp/session_stats.log` - 세션 통계 로그

---

### 7. `common.h` - 공통 헤더

**역할:** 공통 정의 및 구조체

**주요 정의:**
- `UDS_SOCKET_PATH` - UDS 소켓 경로 (`/tmp/mini_ids_packets.sock`)
- `SNAP_LEN` - 최대 패킷 크기 (65535)
- `uds_packet_t` - UDS 패킷 구조체
  ```c
  typedef struct {
      uint32_t packet_len;
      uint64_t timestamp_sec;
      uint32_t timestamp_usec;
      uint8_t packet_data[SNAP_LEN];
  } uds_packet_t;
  ```

---

### 8. 설정 파일

#### `snort.lua` - Snort3 설정
- 네트워크 변수 (HOME_NET, EXTERNAL_NET)
- IPS 규칙 설정
- DAQ 모듈 설정 (pcap, passive)
- 출력 설정 (alert_fast)
- 플러그인 경로
- 인스펙터 활성화 (stream, normalizer, session_stats)

#### `local.rules` - Snort 규칙
- ICMP 탐지 규칙
- TCP/UDP 탐지 규칙 (포트별)
- Alert 메시지 정의

---

## 전체 시스템 흐름도

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mini-IDS 시스템                          │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐
│   main.c     │
│              │
│ 1. veth 생성 │
│ 2. 스레드 생성│
│ 3. 시그널 처리│
└──────┬───────┘
       │
       ├─────────────────┬──────────────────┬──────────────────┐
       │                 │                  │                  │
       ▼                 ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ capture.c    │  │ inject.c     │  │alert_monitor.c│  │veth_manager.c│
│              │  │              │  │              │  │              │
│ 패킷 캡처      │  │ 패킷 주입      │   │ 위협 모니터링   │  │ veth 관리     │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │                  │
       │                 │                  │                  │
       ▼                 │                  │                  │
┌──────────────┐         │                  │                  │
│ libpcap      │         │                  │                  │
│ (eth0)       │         │                  │                  │
└──────┬───────┘         │                  │                  │
       │                 │                  │                  │
       │ 패킷 캡처         │                  │                  │
       ▼                 │                  │                  │
┌──────────────┐         │                  │                  │
│ UDS DGRAM    │────────►│                  │                  │
│ (송신)        │         │                  │                  │
└──────────────┘         │                  │                  │
                        │                  │                  │
                        ▼                  │                  │
                 ┌──────────────┐         │                  │
                 │ UDS DGRAM    │         │                  │
                 │ (수신)        │         │                  │
                 └──────┬───────┘         │                  │
                        │                 │                  │
                        │ 패킷 수신         │                  │
                        ▼                 │                  │
                 ┌──────────────┐         │                  │
                 │ RAW Socket   │         │                  │
                 │ (AF_PACKET)  │         │                  │
                 └──────┬───────┘         │                  │
                        │                 │                  │
                        │ 패킷 주입         │                  │
                        ▼                 │                  │
                 ┌──────────────┐         │                  │
                 │   veth0      │─────────┼──────────────────┘
                 │              │         │
                 └──────┬───────┘         │
                        │                 │
                        │ 패킷 전달         │
                        ▼                 │
                 ┌──────────────┐         │
                 │   veth1      │         │
                 └──────┬───────┘         │
                        │                 │
                        │ 패킷 캡처         │
                        ▼                 │
                 ┌──────────────┐         │
                 │   Snort3     │         │
                 │              │         │
                 │ 1. 패킷 분석   │         │
                 │ 2. 규칙 매칭   │         │
                 │ 3. Alert 생성 │         │
                 │ 4. 플러그인    │         │
                 └──────┬───────┘         │
                        │                 │
                        ├─────────────────┼──────────────────┐
                        │                 │                  │
                        ▼                 ▼                  ▼
                 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                 │alert_fast.txt│  │session_stats │  │session_stats │
                 │              │  │.so (플러그인)  │  │.log          │
                 │ Alert 로그    │  │              │  │ 세션 통계      │
                 └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                        │                 │                  │
                        └─────────────────┴──────────────────┘
                                         │
                                         │ 파일 읽기
                                         ▼
                                 ┌──────────────┐
                                 │alert_monitor │
                                 │              │
                                 │ 1. 세션 로그   │
                                 │    파싱       │
                                 │ 2. Alert 로그 │
                                 │    파싱       │
                                 │ 3. 결합       │
                                 │ 4. 스코어      │
                                 │    계산       │
                                 │ 5. Top 10    │
                                 │    표시       │
                                 └──────┬───────┘
                                        │
                                        │ 대시보드 출력
                                        ▼
                                 ┌──────────────┐
                                 │   콘솔 출력    │
                                 │  (2초마다)    │
                                 └──────────────┘
```

---

## 데이터 흐름

### 1. 패킷 캡처 → 주입 흐름

```
eth0 (물리 인터페이스)
  │
  │ libpcap 캡처
  ▼
capture.c::packet_handler()
  │
  │ UDS 패킷 구조체 변환
  ▼
capture.c::send_to_inject()
  │
  │ UDS DGRAM 전송
  ▼
/tmp/mini_ids_packets.sock (UDS)
  │
  │ UDS DGRAM 수신
  ▼
inject.c::packet_processing_loop()
  │
  │ MAC 주소 재작성
  ▼
inject.c::inject_packet_to_veth0()
  │
  │ RAW Socket 전송
  ▼
veth0 (가상 인터페이스)
  │
  │ 패킷 전달
  ▼
veth1 (가상 인터페이스)
  │
  │ Snort3 캡처
  ▼
Snort3
```

### 2. Snort3 → Alert Monitor 흐름

```
Snort3
  │
  ├─► session_stats_inspector.cc::eval()
  │   │
  │   │ 세션 통계 수집
  │   │
  │   └─► flush_stats() (1초마다)
  │       │
  │       └─► /tmp/session_stats.log
  │
  └─► 규칙 매칭
      │
      └─► Alert 생성
          │
          └─► /tmp/alert_fast.txt
              │
              │ 파일 읽기
              ▼
          alert_monitor.c::print_top_threats()
              │
              │ 세션 로그 + Alert 로그 결합
              │ 스코어 계산
              │ Top 10 정렬
              │
              └─► 콘솔 대시보드 출력
```

### 3. 스레드 간 통신

```
┌─────────────────┐
│  main.c         │
│  (메인 스레드)   │
└────────┬────────┘
         │
         ├─► pthread_create(capture_thread)
         │   │
         │   └─► capture.c::capture_thread_main()
         │       └─► UDS 송신 소켓
         │
         ├─► pthread_create(inject_thread)
         │   │
         │   └─► inject.c::inject_thread_main()
         │       ├─► UDS 수신 소켓
         │       └─► RAW 소켓
         │
         └─► pthread_create(alert_monitor_thread)
             │
             └─► alert_monitor.c::alert_monitor_thread_main()
                 └─► 파일 읽기 (2초마다)
```

---

## 주요 데이터 구조

### `uds_packet_t` (common.h)
```c
typedef struct {
    uint32_t packet_len;        // 패킷 길이
    uint64_t timestamp_sec;     // 타임스탬프 (초)
    uint32_t timestamp_usec;    // 타임스탬프 (마이크로초)
    uint8_t packet_data[SNAP_LEN]; // 패킷 원시 데이터
} uds_packet_t;
```

### `combined_entry_t` (alert_monitor.h)
```c
typedef struct {
    char src_ip[64];
    uint16_t src_port;
    char dst_ip[64];
    uint16_t dst_port;
    unsigned char protocol;
    uint64_t packets;
    uint64_t bytes;
    time_t timestamp;
    int has_alert;
    char alert_msg[256];
    double score;
} combined_entry_t;
```

---

## 주요 설정값

- **UDS 소켓 버퍼**: 1MB (fallback 512KB)
- **RAW 소켓 버퍼**: 1MB (fallback 512KB)
- **최대 패킷 크기**: 200KB (UDS 제한)
- **veth MTU**: 9000 bytes
- **세션 로그 flush 간격**: 1초
- **대시보드 갱신 간격**: 2초
- **세션 유효 시간**: 60초

---

## 의존성

- **libpcap**: 패킷 캡처
- **libnl-3, libnl-route-3**: Netlink API (veth 관리)
- **pthread**: 멀티스레딩
- **Snort3**: 침입 탐지 엔진
- **C++14**: 플러그인 컴파일

---

## 빌드 및 실행

```bash
# 빌드
make

# 실행 (스크립트 사용)
sudo ./start_mini_ids.sh

# 또는 직접 실행
sudo ./mini-ids eth0
```

---

## 로그 파일

- `/tmp/mini-ids.log` - mini-ids 프로그램 로그
- `/tmp/session_stats.log` - 세션 통계 로그
- `/tmp/alert_fast.txt` - Snort Alert 로그
- `/tmp/debug_proto.log` - 플러그인 디버그 로그

