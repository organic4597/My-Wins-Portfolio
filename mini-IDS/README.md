# mini-IDS - Snort3 기반 침입 탐지 시스템

## 🎯 개요
libpcap과 Snort3를 활용한 경량 멀티쓰레드 IDS 시스템입니다. 실제 네트워크 인터페이스에서 패킷을 캡처하여 가상 인터페이스(veth)를 통해 Snort3로 전달하고, 실시간 위협 모니터링을 제공합니다.

## 🚀 빠른 시작

```bash
# 1. 빌드
make clean && make

# 2. 실행
sudo ./start_mini_ids.sh

# 3. 상태 확인
./status_mini_ids.sh

# 4. 종료
sudo ./stop_mini_ids.sh
```

**자세한 사용법**: [QUICK_START.md](QUICK_START.md)

## 🏗️ 아키텍처

```
┌──────────────┐
│  Physical    │
│  Network     │
│   (eth0)     │
└──────┬───────┘
       │
┌──────▼───────────────────────────────────────────┐
│             mini-ids (3 Threads)                 │
│                                                  │
│  ┌─────────────┐       ┌──────────────┐        │
│  │  Capture    │──UDS──│   Inject     │        │
│  │  Thread     │       │   Thread     │        │
│  │  (libpcap)  │       │ (raw socket) │        │
│  └─────────────┘       └──────┬───────┘        │
│                                │                │
│                          ┌─────▼─────┐          │
│                          │   veth0   │          │
│                          └───────────┘          │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │      Alert Monitor Thread                │   │
│  │   (Top 10 Threat Dashboard)              │   │
│  └──────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
                          │
                    ┌─────▼─────┐
                    │   veth1   │
                    └─────┬─────┘
                          │
        ┌─────────────────▼────────────────────┐
        │           Snort3 Engine              │
        │  + session_stats_inspector.so        │
        └─────────────┬────────────────────────┘
                      │
        ┌─────────────┴────────────────────┐
        │                                  │
┌───────▼────────┐              ┌─────────▼──────────┐
│  alert_fast    │              │  session_stats.log │
│    (Alerts)    │              │   (Statistics)     │
└────────────────┘              └────────────────────┘
```

## 📦 구성 요소

### 핵심 소스 코드
- **main.c** - 메인 프로그램 및 쓰레드 관리
- **capture.c** - 패킷 캡처 쓰레드 (eth0 → UDS)
- **inject.c** - 패킷 주입 쓰레드 (UDS → veth0)
- **alert_monitor.c** - 실시간 Top 10 위협 모니터링 ⭐
- **veth_manager.c** - 가상 네트워크 인터페이스 관리
- **session_stats_inspector.cc** - Snort3 플러그인 (세션 통계 수집)

### 실행 스크립트
- **start_mini_ids.sh** - 전체 시스템 자동 시작
- **stop_mini_ids.sh** - 시스템 종료 및 정리
- **status_mini_ids.sh** - 실시간 상태 확인

### 설정 파일
- **snort.lua** - Snort3 설정
- **local.rules** - 침입 탐지 룰
- **Makefile** - 빌드 자동화

## 🎨 주요 특징

### 1. 멀티쓰레드 아키텍처
- **독립 실행**: 한 쓰레드 장애 시 다른 쓰레드 영향 없음
- **비동기 처리**: 캡처, 주입, 모니터링 병렬 수행
- **효율적인 리소스 사용**: pthread 기반

### 2. 실시간 위협 모니터링 ⭐
- **Top 10 Dashboard**: 위험도 스코어 기반 정렬
- **자동 갱신**: 60초 주기
- **컬러 출력**: Alert 있는 세션 빨간색 표시
- **통합 분석**: Session stats + Snort alerts

### 3. 자동화
- **한 번의 명령**: `start_mini_ids.sh`로 전체 시스템 시작
- **자동 정리**: 기존 프로세스 및 veth 정리
- **백그라운드 실행**: 데몬 모드 지원

## 📊 세션 통계 수집

### 출력 위치
- `/tmp/session_stats.log` (60초마다 flush)
- `/tmp/alert_fast.txt` (Snort alerts)

### 포맷
```
timestamp | src_ip:port | dst_ip:port | protocol | packets | bytes
```

### 예시
```
1763031798|192.168.0.102:59555|162.159.135.234:443|6|4|240
1763031798|185.199.110.154:443|192.168.0.5:54748|6|1|66
```

## 🛠️ 빌드 및 설치

### 의존성
```bash
# Debian/Ubuntu/Kali
sudo apt install build-essential libpcap-dev libnl-3-dev libnl-route-3-dev

# Snort3는 별도 설치 필요
# 설치 경로: /usr/local/snort/
```

### 빌드
```bash
cd /path/to/mini-IDS
make clean
make
```

빌드 결과:
- `mini-ids` - 메인 실행 파일
- `session_stats.so` - Snort3 플러그인

## 🔍 로그 모니터링

```bash
# mini-IDS 로그
tail -f /tmp/mini-ids.log

# Snort3 로그
tail -f /tmp/snort.log

# Alert 실시간 모니터링
tail -f /tmp/alert_fast.txt

# 세션 통계
tail -f /tmp/session_stats.log
```

## 🐛 트러블슈팅

### 권한 오류
```bash
# root 권한 필요
sudo ./start_mini_ids.sh
```

### veth 생성 실패
```bash
# 수동 생성
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up mtu 65535
sudo ip link set veth1 up mtu 65535
```

### Snort 플러그인 로드 실패
```bash
# 플러그인 확인
snort --plugin-path . --list-plugins | grep session_stats

# 재빌드
make clean && make
```

### 프로세스 정리
```bash
# 강제 종료
sudo pkill -9 mini-ids
sudo pkill -9 snort

# veth 삭제
sudo ip link delete veth0
```

## 📈 위협 스코어 계산

```
스코어 = (패킷 수 × 10) + (바이트 수 / 1024) + (Alert 있으면 +1000)
```

- Alert가 있으면 자동으로 상위권
- 트래픽 양 (패킷, 바이트) 고려
- 최근 60초 세션만 분석

## 🔧 개발 환경

- **OS**: Kali Linux / Ubuntu
- **Compiler**: GCC/G++ (C++14 이상)
- **Snort**: 3.x
- **Libraries**: libpcap, libnl-3, pthread

## 📄 라이센스

MIT License

## 🙋 지원

문제 발생 시:
1. `./status_mini_ids.sh` 실행
2. `/tmp/mini-ids.log` 확인
3. [QUICK_START.md](QUICK_START.md) 참고
