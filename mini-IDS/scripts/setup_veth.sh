#!/bin/bash
#
# scripts/setup_veth.sh
#
# mini-IDS 프로젝트를 위한 가상 이더넷(veth) 페어를 생성합니다.
# veth0: 패킷 주입용 (injector가 사용)
# veth1: 패킷 리스닝용 (Snort가 사용)
#
# 실행 방법: sudo bash scripts/setup_veth.sh create
# 삭제 방법: sudo bash scripts/setup_veth.sh delete

set -e  # 오류 발생 시 스크립트 중단
set -u  # 정의되지 않은 변수 사용 시 중단

# --- 변수 설정 ---
IFACE0="veth0"
IFACE1="veth1"
# ------------------

# 루트 권한 확인
if [ "$EUID" -ne 0 ]; then
  echo "오류: 이 스크립트는 루트(sudo) 권한으로 실행해야 합니다."
  exit 1
fi

# 기능: veth 생성
create_veth() {
    echo "[$IFACE0 <--> $IFACE1] veth 페어를 생성합니다..."
    
    # 1. veth 페어 생성
    # 이미 존재하는지 확인
    if ip link show $IFACE0 > /dev/null 2>&1; then
        echo "경고: $IFACE0 인터페이스가 이미 존재합니다. 삭제 후 다시 시도합니다."
        delete_veth
    fi
    
    ip link add $IFACE0 type veth peer name $IFACE1
    
    # 2. 각 인터페이스 활성화 (up)
    ip link set $IFACE0 up
    ip link set $IFACE1 up
    
    # 3. (중요) Snort가 리스닝할 인터페이스(IFACE1)의 Promiscuous mode 활성화
    # 이 모드가 켜져 있어야 인터페이스로 들어오는 모든 패킷을 수신할 수 있습니다.
    ip link set $IFACE1 promisc on
    
    echo "[$IFACE0 <--> $IFACE1] veth 페어 생성 및 활성화 완료."
    echo "  - $IFACE0: (UP)"
    echo "  - $IFACE1: (UP, Promiscuous)"
    
    echo "확인:"
    ip link show $IFACE0
    ip link show $IFACE1
}

# 기능: veth 삭제
delete_veth() {
    echo "[$IFACE0] veth 인터페이스를 삭제합니다..."
    
    if ip link show $IFACE0 > /dev/null 2>&1; then
        ip link delete $IFACE0
        echo "[$IFACE0] 및 피어 [$IFACE1] 삭제 완료."
    else
        echo "[$IFACE0] 인터페이스가 존재하지 않습니다."
    fi
}

# --- 메인 로직 ---
ACTION=${1:-"create"} # 기본값은 'create'

if [ "$ACTION" == "create" ]; then
    create_veth
elif [ "$ACTION" == "delete" ]; then
    delete_veth
else
    echo "사용법: $0 [create|delete]"
    exit 1
fi