#!/bin/bash
# Snort3 간단 테스트

echo "========================================="
echo "  Snort3 + mini-IDS 테스트"
echo "========================================="

if [ "$EUID" -ne 0 ]; then 
   echo "[ERROR] root 권한 필요: sudo $0"
   exit 1
fi

# 기존 프로세스 정리
pkill -9 mini-ids 2>/dev/null || true
pkill -9 snort 2>/dev/null || true
sleep 1

# mini-IDS 시작
echo "[1] mini-IDS 시작..."
./mini-ids eth0 > /tmp/mini-ids.log 2>&1 &
MINI_PID=$!
echo "    PID: $MINI_PID"

# veth1 대기
echo "[2] veth1 생성 대기..."
for i in {1..10}; do
    if ip link show veth1 &>/dev/null; then
        echo "    veth1 준비 완료!"
        break
    fi
    sleep 1
done

# Snort3 시작
echo "[3] Snort3 시작 (veth1 모니터링)..."
echo "    간단한 패킷 덤프 모드로 실행"

# 간단한 패킷 수신 확인 (룰 없이)
snort -i veth1 -A alert_fast -q -c /dev/null 2>&1 &
SNORT_PID=$!
echo "    PID: $SNORT_PID"

sleep 3

# 트래픽 생성
echo "[4] 테스트 트래픽 생성..."
ping -c 5 8.8.8.8 &

sleep 5

echo ""
echo "========================================="
echo "  결과"
echo "========================================="
echo "[mini-IDS 로그]"
tail -10 /tmp/mini-ids.log

echo ""
echo "Ctrl+C로 종료"
trap "kill $MINI_PID $SNORT_PID 2>/dev/null; exit 0" SIGINT
wait
