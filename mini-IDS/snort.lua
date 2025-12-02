---------------------------------------------------------------------------
-- Snort3 로컬 설정 파일
---------------------------------------------------------------------------

-- 1. 네트워크 변수: 모니터링할 네트워크를 정의합니다.
-- 'any'는 모든 IP 주소를 의미합니다.
HOME_NET = 'any'
EXTERNAL_NET = 'any'


-- 2. IPS (침입 방지 시스템) 설정
ips = {
    -- Snort에 내장된 기본 규칙을 활성화합니다.
    enable_builtin_rules = true,

    -- 사용자 정의 규칙 파일을 지정합니다.
    -- local.rules 파일의 전체 경로를 지정해야 합니다.
    rules = [[
include /home/kali/Desktop/wins-prj/mini-IDS/local.rules
    ]],
}


-- 3. DAQ (데이터 수집) 모듈 설정
-- pcap DAQ를 사용하여 수동 모드(passive)로 네트워크 인터페이스에서 패킷을 읽습니다.
daq = {
    --module_path = '/usr/local/lib/snort/daq', -- 경로가 시스템마다 다를 수 있어 주석 처리
    modules = { { name = 'pcap', mode = 'passive' } }
}


-- 4. 출력 및 로깅 설정
-- Snort가 생성하는 로그 파일이 저장될 디렉토리입니다.
-- start_mini_ids.sh 스크립트의 '-l /tmp' 옵션이 이 설정을 덮어쓸 수 있습니다.
output = {
    logdir = '/tmp'
}

-- alert_fast: 빠른 형식의 알림을 생성합니다.
-- 파일로 저장되며, 저장 위치는 'output.logdir' 또는 -l 옵션으로 지정됩니다.
alert_fast = {
    file = true
}


-- 5. 플러그인 경로 설정
-- session_stats.so 플러그인을 로드하기 위한 경로
plugin_path = '/usr/local/snort/lib/snort_extra'

-- 6. 인스펙터 활성화
-- 네트워크 트래픽의 상태를 추적하고 정규화하기 위해 필요합니다.
stream = {}
normalizer = {}

-- 7. 체크섬 검증 비활성화
-- veth로 주입된 패킷의 체크섬이 유효하지 않을 수 있으므로 비활성화
network = {
    checksum_eval = 'none'
}

-- session_stats inspector 추가
session_stats = {}

-- 아래는 다른 유용한 인스펙터들의 예시입니다. 필요에 따라 주석을 해제하여 사용할 수 있습니다.
-- http_inspect = {}
-- file_id = { file_rules = '/path/to/your/file_magic.rules' }