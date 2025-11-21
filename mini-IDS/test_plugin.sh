#!/bin/bash

echo "Testing session_stats plugin..."
echo ""

# 플러그인 파일 확인
if [ -f session_stats.so ]; then
    echo "✓ Plugin file exists: session_stats.so"
    file session_stats.so
else
    echo "✗ Plugin file not found!"
    exit 1
fi

echo ""
echo "Testing Snort plugin loading..."
sudo /usr/local/snort/bin/snort --plugin-path /home/kali/Desktop/wins-prj/mini-IDS --list-plugins 2>&1 | grep -i session || echo "Plugin not found in list"

echo ""
echo "Creating test session_stats.log file..."
sudo touch /tmp/session_stats.log
sudo chmod 666 /tmp/session_stats.log
echo "✓ Created /tmp/session_stats.log with permissions"

echo ""
echo "Test complete. Now restart Snort and check if plugin loads:"
echo "  Look for: [session_stats] mod_ctor called - module loading"
echo "  Look for: [session_stats] ss_ctor called - inspector creating"

