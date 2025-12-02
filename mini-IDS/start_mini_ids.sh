#!/bin/bash

# mini-IDS 시작 스크립트
# Snort3를 백그라운드로 실행하고, mini-ids 대시보드는 터미널에 직접 표시

# Exit on error
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping processes and cleaning up..."
    # Kill Snort background process
    if [ ! -z "$SNORT_PID" ]; then
        sudo kill $SNORT_PID 2>/dev/null || true
        wait $SNORT_PID 2>/dev/null || true
    fi
    # Delete the veth pair
    sudo ip link del veth0 2>/dev/null || true
    echo "Cleanup complete."
}

# Trap signals to run cleanup
trap cleanup EXIT

# Clean up previous network interfaces
sudo ip link del veth0 2>/dev/null || true
sudo rm -f /tmp/alert_fast.txt /tmp/session_stats.log 2>/dev/null || true

# veth 쌍 생성 및 설정
echo "Creating veth pair..."
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 mtu 9000
sudo ip link set veth1 mtu 9000
sudo ip link set veth0 up
sudo ip link set veth1 up
echo "✓ veth pair created (MTU 9000)"

# Snort3를 백그라운드에서 실행
echo "Starting Snort3..."
sudo /usr/local/snort/bin/snort \
    -c "$SCRIPT_DIR/snort.lua" \
    --plugin-path /usr/local/snort/lib/snort_extra \
    -i veth1 \
    -A alert_fast \
    -l /tmp \
    -q &
SNORT_PID=$!
echo "✓ Snort3 started (PID: $SNORT_PID)"

# Snort가 준비될 때까지 잠시 대기
sleep 2

echo ""
echo "============================================"
echo "  🛡️  mini-IDS 실시간 모니터링 시작"
echo "  Ctrl+C로 종료"
echo "============================================"
echo ""

# mini-ids를 포그라운드에서 실행 (대시보드 직접 표시)
sudo ./mini-ids eth0
