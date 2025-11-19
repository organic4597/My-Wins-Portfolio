#!/bin/bash

# Mini-IDS 상태 확인 스크립트

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Root 권한 확인 (로그 읽기 위해 필요)
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[INFO] 일부 로그는 root 권한이 필요합니다${NC}"
    echo -e "${YELLOW}[INFO] 전체 정보 확인: sudo $0${NC}"
    echo ""
fi

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           📊 MINI-IDS 상태 확인                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# 프로세스 상태
echo -e "${GREEN}[프로세스 상태]${NC}"
if pgrep -x mini-ids > /dev/null 2>&1; then
    PID=$(pgrep -x mini-ids | head -1)
    UPTIME=$(ps -p $PID -o etime= 2>/dev/null | xargs)
    echo -e "  ${GREEN}✓${NC} mini-IDS: 실행 중 (PID: ${PID}, 가동시간: ${UPTIME})"
else
    echo -e "  ${RED}✗${NC} mini-IDS: 중지됨"
fi

# Snort 프로세스는 정확한 이름이 아닐 수 있으므로 grep 사용
if pgrep -f "snort.*veth1" > /dev/null 2>&1; then
    PID=$(pgrep -f "snort.*veth1" | head -1)
    UPTIME=$(ps -p $PID -o etime= 2>/dev/null | xargs)
    echo -e "  ${GREEN}✓${NC} Snort3: 실행 중 (PID: ${PID}, 가동시간: ${UPTIME})"
else
    echo -e "  ${RED}✗${NC} Snort3: 중지됨"
fi

echo ""
echo -e "${GREEN}[네트워크 인터페이스]${NC}"
if ip link show veth0 &> /dev/null; then
    VETH0_STATE=$(ip link show veth0 | grep -oP 'state \K\w+')
    echo -e "  ${GREEN}✓${NC} veth0: ${VETH0_STATE}"
else
    echo -e "  ${RED}✗${NC} veth0: 존재하지 않음"
fi

if ip link show veth1 &> /dev/null; then
    VETH1_STATE=$(ip link show veth1 | grep -oP 'state \K\w+')
    echo -e "  ${GREEN}✓${NC} veth1: ${VETH1_STATE}"
else
    echo -e "  ${RED}✗${NC} veth1: 존재하지 않음"
fi

echo ""
echo -e "${GREEN}[로그 파일]${NC}"
if [ -f /tmp/mini-ids.log ]; then
    SIZE=$(sudo du -h /tmp/mini-ids.log 2>/dev/null | cut -f1)
    LINES=$(sudo wc -l < /tmp/mini-ids.log 2>/dev/null || echo "0")
    echo -e "  mini-IDS: ${SIZE} (${LINES} lines)"
else
    echo -e "  mini-IDS: 파일 없음"
fi

if [ -f /tmp/snort.log ]; then
    SIZE=$(sudo du -h /tmp/snort.log 2>/dev/null | cut -f1)
    LINES=$(sudo wc -l < /tmp/snort.log 2>/dev/null || echo "0")
    echo -e "  Snort3:   ${SIZE} (${LINES} lines)"
else
    echo -e "  Snort3: 파일 없음"
fi

if [ -f /tmp/session_stats.log ]; then
    SIZE=$(sudo du -h /tmp/session_stats.log 2>/dev/null | cut -f1)
    LINES=$(sudo wc -l < /tmp/session_stats.log 2>/dev/null || echo "0")
    echo -e "  Session:  ${SIZE} (${LINES} sessions)"
else
    echo -e "  Session: 파일 없음"
fi

if [ -f /tmp/alert_fast.txt ]; then
    SIZE=$(sudo du -h /tmp/alert_fast.txt 2>/dev/null | cut -f1)
    LINES=$(sudo wc -l < /tmp/alert_fast.txt 2>/dev/null || echo "0")
    echo -e "  Alert:    ${SIZE} (${LINES} alerts)"
else
    echo -e "  Alert: 파일 없음"
fi

echo ""
echo -e "${GREEN}[최근 Alert (최근 5개)]${NC}"
if [ -f /tmp/alert_fast.txt ] && [ -s /tmp/alert_fast.txt ]; then
    sudo tail -5 /tmp/alert_fast.txt 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${YELLOW}→${NC} ${line:0:80}..."
    done
else
    echo -e "  ${BLUE}(Alert 없음)${NC}"
fi

echo ""
echo -e "${GREEN}[최근 세션 (최근 5개)]${NC}"
if [ -f /tmp/session_stats.log ] && [ -s /tmp/session_stats.log ]; then
    sudo tail -5 /tmp/session_stats.log 2>/dev/null | while IFS='|' read -r ts src dst proto pkts bytes; do
        echo -e "  ${YELLOW}→${NC} ${src} -> ${dst} | Proto:${proto} | Pkts:${pkts} | Bytes:${bytes}"
    done
else
    echo -e "  ${BLUE}(세션 없음)${NC}"
fi

echo ""
