#!/bin/bash

# 빠른 트래픽 테스트 - 간단 버전
# 사용법: ./quick_traffic.sh

echo "🌐 Quick Traffic Test"
echo "===================="
echo ""

# ICMP
echo "[1/3] ICMP (Ping)..."
ping -c 5 8.8.8.8 &
ping -c 5 1.1.1.1 &
wait
echo "✓ 10 ICMP packets sent"
echo ""

# DNS
echo "[2/3] DNS Queries..."
for domain in google.com github.com youtube.com; do
    nslookup $domain > /dev/null 2>&1 &
done
wait
echo "✓ 3 DNS queries sent"
echo ""

# HTTP
echo "[3/3] HTTP Requests..."
curl -s http://example.com > /dev/null &
curl -s http://neverssl.com > /dev/null &
wait
echo "✓ 2 HTTP requests sent"
echo ""

echo "✅ Test Complete!"
echo ""
echo "📊 Check results:"
echo "   sudo tail -20 /tmp/alert_fast.txt"
echo "   sudo tail -20 /tmp/session_stats.log"
echo ""
