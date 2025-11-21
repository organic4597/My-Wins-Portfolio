#!/bin/bash

echo "=== Mini-IDS 로그 정리 ==="

# 프로세스 종료
echo "1. 프로세스 종료 중..."
sudo ./stop_mini_ids.sh 2>/dev/null || true
sleep 2

# 로그 파일 삭제
echo "2. 로그 파일 삭제 중..."
sudo rm -f /tmp/session_stats.log
sudo rm -f /tmp/alert_fast.txt
sudo rm -f /tmp/mini-ids.log
sudo rm -f /tmp/debug_proto.log

echo "3. 로그 파일 확인..."
ls -lh /tmp/session_stats.log /tmp/alert_fast.txt /tmp/mini-ids.log /tmp/debug_proto.log 2>/dev/null || echo "모든 로그 파일이 삭제되었습니다."

echo ""
echo "=== 로그 정리 완료 ==="
echo ""
echo "이제 다음 명령으로 시스템을 시작하세요:"
echo "  sudo ./start_mini_ids.sh"

