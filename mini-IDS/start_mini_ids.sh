#!/bin/bash

# Exit on error
set -e

# Cleanup function
cleanup() {
    echo "Stopping processes and cleaning up..."
    # Kill background processes
    if [ ! -z "$SNORT_PID" ]; then
        sudo kill $SNORT_PID 2>/dev/null
    fi
    if [ ! -z "$MINI_IDS_PID" ]; then
        sudo kill $MINI_IDS_PID 2>/dev/null
    fi
    # Delete the veth pair
    sudo ip link del veth0 2>/dev/null
    echo "Cleanup complete."
}

# Trap SIGINT and EXIT signals to run cleanup
trap cleanup SIGINT EXIT

# Clean up previous network interfaces to prevent errors
sudo ip link del veth0 2>/dev/null || true

# veth 쌍 생성 및 설정
echo "Creating veth pair..."
sudo ip link add veth0 type veth peer name veth1
# MTU를 9000으로 설정 (큰 패킷 처리)
sudo ip link set veth0 mtu 9000
sudo ip link set veth1 mtu 9000
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip addr add 10.0.0.2/24 dev veth1
echo "veth pair created with MTU 9000."

# Snort를 백그라운드에서 실행 (veth1에서 패킷 캡처)
# mini-ids가 eth0에서 캡처한 패킷을 veth0으로 주입하면 veth1으로 전달됨
# 로컬 snort.lua 설정 파일을 사용
echo "Starting Snort..."
# 플러그인 경로를 명시적으로 지정
sudo /usr/local/snort/bin/snort -c /home/kali/Desktop/wins-prj/mini-IDS/snort.lua --plugin-path /home/kali/Desktop/wins-prj/mini-IDS -i veth1 -A alert_fast -l /tmp &
SNORT_PID=$!
echo "Snort started with PID: $SNORT_PID"

# mini-ids 프로그램 실행 (eth0에서 패킷 캡처)
echo "Starting mini-IDS..."
# 백그라운드로 실행하되 출력은 로그 파일로
sudo ./mini-ids eth0 > /tmp/mini-ids.log 2>&1 &
MINI_IDS_PID=$!
echo "mini-ids started with PID: $MINI_IDS_PID"
echo "Logs are being written to /tmp/mini-ids.log"
echo "Waiting for mini-ids to initialize..."
sleep 3
# 초기 로그 확인
if [ -f /tmp/mini-ids.log ] && [ -s /tmp/mini-ids.log ]; then
    echo "=== Initial mini-ids output ==="
    sudo tail -30 /tmp/mini-ids.log
    echo "================================"
    echo ""
    echo "Checking for capture thread..."
    if sudo grep -q "CAPTURE.*스레드 시작\|CAPTURE.*UDS 소켓\|MAIN.*capture 스레드" /tmp/mini-ids.log; then
        echo "✓ Capture thread appears to be running"
    else
        echo "⚠ Warning: Capture thread messages not found in log"
    fi
else
    echo "Warning: Log file not created or empty"
    echo "Checking if process is running..."
    if ps -p $MINI_IDS_PID > /dev/null 2>&1; then
        echo "Process is running (PID: $MINI_IDS_PID)"
    else
        echo "Process is not running!"
    fi
fi
echo ""
echo "You can monitor logs with: sudo tail -f /tmp/mini-ids.log"
echo ""

# 사용자가 중지할 때까지 대기
read -p "Press [Enter] to stop..."
