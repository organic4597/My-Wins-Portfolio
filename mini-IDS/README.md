# mini-IDS

Linux 환경에서 NFV/컨테이너 트래픽을 미러링하고 Snort 3와 연동하여 침입 탐지를 수행하는 경량화된 패킷 파이프라인 프로젝트입니다.

## 1. 프로젝트 개요 (Description)

본 프로젝트는 고성능 패킷 캡처, 권한 분리, Unix Domain Socket (UDS)을 이용한 프로세스 간 통신(IPC)을 통해 veth (Virtual Ethernet) 인터페이스로 트래픽을 주입(inject)합니다. 주입된 트래픽은 Snort 3와 같은 IDS/IPS 솔루션이 분석할 수 있도록 전달하는 어댑터 역할을 수행합니다.

주요 목표는 다음과 같습니다.
* **고성능 캡처:** `AF_PACKET (TPACKET_V3)` 또는 `pcap`을 이용한 효율적인 패킷 캡처.
* **보안 (권한 분리):** 패킷 주입에 필요한 `CAP_NET_RAW` 권한을 최소한의 프로세스(`veth_inject`)에만 부여.
* **모듈식 설계:** `capture`, `sender`, `adapter`, `veth_inject` 등 각 기능을 독립된 C 프로그램으로 분리.
* **이벤트 집계:** Snort 3 알림을 수집하여 실시간으로 집계 및 이벤트화.

## 2. 아키텍처 (Architecture)

(계획서의 설계를 바탕으로 간단한 다이어그램이나 흐름도를 이곳에 추가하면 좋습니다.)

1.  **`capture`**: 실제 NIC에서 패킷 캡처 (e.g., `eth0`)
2.  **`sender`**: 캡처된 패킷을 UDS(Unix Domain Socket)를 통해 전송
3.  **`adapter`**: UDS 수신, 송신자(`sender`) 권한 검증 (`SO_PEERCRED`), 패킷 정규화 후 `veth_inject`로 전달
4.  **`veth_inject`**: (`CAP_NET_RAW` 보유) `adapter`로부터 받은 패킷을 가상 인터페이스(`veth0`)로 주입
5.  **`veth-pair`**: `veth0` ↔ `veth1`
6.  **`Snort 3`**: `veth1` 인터페이스를 리스닝하며 룰 기반 탐지
7.  **`alerts`**: Snort 알림(alert)을 수집하여 60초 슬라이딩 윈도우로 집계
8.  **`client`**: 집계된 이벤트를 모니터링

## 3. 개발 환경 구성 (Getting Started)

### 사전 요구사항
* Linux (Ubuntu/Debian/Fedora 등)
* `gcc` (or `clang`), `make`
* `libpcap-dev`
* `snort3` (테스트용)

### 설치 및 veth 설정
1.  리포지토리 클론:
    ```bash
    git clone [https://github.com/organic4597/My-Wins-Portfolio.git](https://github.com/organic4597/My-Wins-Portfolio.git)
    cd My-Wins-Portfolio
    ```

2.  (TODO) veth 생성 스크립트 실행:
    ```bash
    bash scripts/setup_veth.sh
    ```

3.  (TODO) Snort 3 설정:
    * `veth1` 인터페이스를 리스닝하도록 설정합니다.

## 4. 사용법 (Usage)

(TODO: 컴포넌트 실행 순서 및 방법 기술)

1.  `capture` 실행
2.  `sender` 실행
3.  `adapter` 실행
4.  `veth_inject` 실행 (특수 권한 필요)
5.  `alerts` 실행

## 5. 컴포넌트 상세

* `src/capture.c`: 패킷 캡처 모듈
* `src/sender.c`: UDS 전송 모듈
* `src/adapter.c`: UDS 수신 및 검증 모듈
* `src/veth_inject.c`: veth 주입 모듈 (권한 분리)
* `src/alerts.c`: 알림 집계 모듈
* `src/client.c`: 이벤트 확인 클라이언트

## 6. 테스트 (Tests)

`tests/` 디렉토리에는 UDS 송수신 테스트 및 통합 테스트를 위한 유틸리티가 포함될 예정입니다.