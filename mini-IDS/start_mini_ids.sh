#!/bin/bash

# Mini-IDS 자동 실행 스크립트
# 사용법: sudo ./start_mini_ids.sh [interface]

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로고 출력
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           🛡️  MINI-IDS 자동 실행 스크립트                ║
║                                                           ║
║   Packet Capture → Inject → Snort3 → Alert Monitor       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[ERROR] root 권한으로 실행해주세요: sudo $0${NC}"
    exit 1
fi

# 인터페이스 설정
INTERFACE=${1:-eth0}
SNORT_BIN="/usr/local/snort/bin/snort"
SNORT_CONFIG="./snort.lua"
VETH_INTERFACE="veth1"

echo -e "${GREEN}[INFO] 설정 확인${NC}"
echo -e "  - 캡처 인터페이스: ${INTERFACE}"
echo -e "  - Snort 분석 인터페이스: ${VETH_INTERFACE}"
echo -e "  - Snort 설정: ${SNORT_CONFIG}"
echo ""

# 인터페이스 존재 확인
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}[ERROR] 인터페이스 '${INTERFACE}'가 존재하지 않습니다${NC}"
    echo -e "${YELLOW}[INFO] 사용 가능한 인터페이스:${NC}"
    ip -br link show
    exit 1
fi

# Snort 실행 파일 확인
if [ ! -f "$SNORT_BIN" ]; then
    echo -e "${RED}[ERROR] Snort3가 설치되지 않았습니다: ${SNORT_BIN}${NC}"
    exit 1
fi

# mini-ids 실행 파일 확인
if [ ! -f "./mini-ids" ]; then
    echo -e "${YELLOW}[WARN] mini-ids 실행 파일이 없습니다. 빌드합니다...${NC}"
    make clean && make
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] 빌드 실패${NC}"
        exit 1
    fi
fi

# 기존 프로세스 정리
echo -e "${YELLOW}[INFO] 기존 프로세스 정리 중...${NC}"
pkill -9 mini-ids 2>/dev/null || true
pkill -9 snort 2>/dev/null || true
sleep 1

# 기존 veth 정리
echo -e "${YELLOW}[INFO] 기존 veth 정리 중...${NC}"
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
sleep 1

# 로그 파일 초기화 (선택적)
echo -e "${YELLOW}[INFO] 로그 파일 초기화...${NC}"
> /tmp/session_stats.log 2>/dev/null || true
> /tmp/alert_fast.txt 2>/dev/null || true

# PID 파일 정리
rm -f /tmp/mini-ids.pid /tmp/snort.pid

# veth 먼저 생성 (mini-IDS 시작 전)
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   단계 1/3: veth 인터페이스 생성${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}[INFO] veth 쌍 생성 중 (veth0 <-> veth1)...${NC}"
ip link add veth0 type veth peer name veth1
if [ $? -eq 0 ]; then
    ip link set veth0 up
    ip link set veth1 up
    ip link set veth0 mtu 65535
    ip link set veth1 mtu 65535
    ip link set veth0 promisc on
    ip link set veth1 promisc on
    ip addr add 10.0.0.1/24 dev veth0 2>/dev/null || true
    ip addr add 10.0.0.2/24 dev veth1 2>/dev/null || true
    echo -e "${GREEN}[OK] veth 인터페이스 생성 완료 (Promiscuous mode)${NC}"
else
    echo -e "${RED}[ERROR] veth 생성 실패${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   단계 2/3: mini-IDS 시작${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

# mini-ids를 백그라운드로 실행
./mini-ids "$INTERFACE" > /tmp/mini-ids.log 2>&1 &
MINI_IDS_PID=$!
echo $MINI_IDS_PID > /tmp/mini-ids.pid

echo -e "${BLUE}[INFO] mini-IDS 시작됨 (PID: ${MINI_IDS_PID})${NC}"
echo -e "${BLUE}[INFO] 로그: /tmp/mini-ids.log${NC}"

# mini-IDS 초기화 대기
echo -e "${YELLOW}[INFO] mini-IDS 초기화 중...${NC}"
sleep 2

# mini-IDS 프로세스 확인
if ! ps -p $MINI_IDS_PID > /dev/null 2>&1; then
    echo -e "${RED}[ERROR] mini-IDS가 시작 직후 종료됨${NC}"
    echo -e "${YELLOW}로그 확인:${NC}"
    tail -20 /tmp/mini-ids.log
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   단계 3/3: Snort3 시작${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

# Snort3 백그라운드 실행
$SNORT_BIN -i "$VETH_INTERFACE" -c "$SNORT_CONFIG" --plugin-path . -A alert_fast -q > /tmp/snort.log 2>&1 &
SNORT_PID=$!
echo $SNORT_PID > /tmp/snort.pid

echo -e "${BLUE}[INFO] Snort3 시작됨 (PID: ${SNORT_PID})${NC}"
echo -e "${BLUE}[INFO] 로그: /tmp/snort.log${NC}"

# Snort 초기화 대기
echo -e "${YELLOW}[INFO] Snort3 초기화 대기 중...${NC}"
sleep 3

# 프로세스 상태 확인
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   시스템 상태 확인${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

if ps -p $MINI_IDS_PID > /dev/null; then
    echo -e "${GREEN}✓ mini-IDS: 실행 중 (PID: ${MINI_IDS_PID})${NC}"
else
    echo -e "${RED}✗ mini-IDS: 실행 실패${NC}"
    echo -e "${YELLOW}로그 확인: tail /tmp/mini-ids.log${NC}"
fi

if ps -p $SNORT_PID > /dev/null; then
    echo -e "${GREEN}✓ Snort3: 실행 중 (PID: ${SNORT_PID})${NC}"
else
    echo -e "${RED}✗ Snort3: 실행 실패${NC}"
    echo -e "${YELLOW}로그 확인: tail /tmp/snort.log${NC}"
fi

# 네트워크 인터페이스 확인
if ip link show veth0 &> /dev/null && ip link show veth1 &> /dev/null; then
    echo -e "${GREEN}✓ veth 인터페이스: veth0 <-> veth1${NC}"
else
    echo -e "${RED}✗ veth 인터페이스: 생성 실패${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   🚀 Mini-IDS 실행 완료!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}[실시간 Alert Monitor 화면]${NC}"
echo -e "  Alert Monitor가 mini-IDS 내부에서 60초마다 화면을 갱신합니다"
echo -e "  로그 파일에서 실시간 출력 확인 중..."
echo ""
echo -e "${YELLOW}[종료 방법]${NC}"
echo -e "  Ctrl+C를 누르면 모니터링이 중지되지만 백그라운드는 계속 실행됩니다"
echo -e "  완전 종료: ./stop_mini_ids.sh"
echo ""

# 트랩 설정 (Ctrl+C 처리)
trap 'echo -e "\n${YELLOW}[INFO] 로그 모니터링 중지. 백그라운드 실행 계속됨.${NC}"; echo -e "${YELLOW}[INFO] 종료하려면: ./stop_mini_ids.sh${NC}"; exit 0' SIGINT SIGTERM

# mini-IDS 로그 실시간 표시 (Alert Monitor 출력 포함)
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Alert Monitor 실시간 화면 (mini-IDS 로그)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
sleep 2

# 로그 tail 표시
tail -f /tmp/mini-ids.log
