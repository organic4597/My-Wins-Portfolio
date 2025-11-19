#!/bin/bash

# Mini-IDS 종료 스크립트

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           🛑 MINI-IDS 종료 스크립트                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[ERROR] root 권한으로 실행해주세요: sudo $0${NC}"
    exit 1
fi

echo -e "${YELLOW}[INFO] Mini-IDS 시스템 종료 중...${NC}"

# PID 파일에서 프로세스 종료
if [ -f /tmp/mini-ids.pid ]; then
    MINI_IDS_PID=$(cat /tmp/mini-ids.pid)
    if ps -p $MINI_IDS_PID > /dev/null 2>&1; then
        echo -e "${BLUE}[INFO] mini-IDS 종료 중 (PID: ${MINI_IDS_PID})${NC}"
        kill $MINI_IDS_PID
        sleep 2
        kill -9 $MINI_IDS_PID 2>/dev/null || true
    fi
    rm -f /tmp/mini-ids.pid
fi

if [ -f /tmp/snort.pid ]; then
    SNORT_PID=$(cat /tmp/snort.pid)
    if ps -p $SNORT_PID > /dev/null 2>&1; then
        echo -e "${BLUE}[INFO] Snort3 종료 중 (PID: ${SNORT_PID})${NC}"
        kill $SNORT_PID
        sleep 2
        kill -9 $SNORT_PID 2>/dev/null || true
    fi
    rm -f /tmp/snort.pid
fi

# 프로세스 이름으로 강제 종료
echo -e "${YELLOW}[INFO] 남은 프로세스 정리 중...${NC}"
pkill -9 mini-ids 2>/dev/null || true
pkill -9 snort 2>/dev/null || true

# veth 인터페이스 삭제
echo -e "${YELLOW}[INFO] veth 인터페이스 정리 중...${NC}"
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true

# Unix Domain Socket 정리
rm -f /tmp/mini_ids.sock 2>/dev/null || true

echo ""
echo -e "${GREEN}✓ Mini-IDS 시스템이 완전히 종료되었습니다${NC}"
echo ""
echo -e "${BLUE}[INFO] 로그 파일은 보존되었습니다:${NC}"
echo -e "  - /tmp/mini-ids.log"
echo -e "  - /tmp/snort.log"
echo -e "  - /tmp/alert_fast.txt"
echo -e "  - /tmp/session_stats.log"
echo ""
