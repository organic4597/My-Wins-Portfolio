---------------------------------------------------------------------------
-- Snort3 설정 파일 (Alert 출력 포함)
---------------------------------------------------------------------------

-- Inspector 플러그인 로드
plugin_path = '/home/kali/Desktop/wins-prj/mini-IDS'

HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
    include = '/home/kali/Desktop/wins-prj/mini-IDS/local.rules',
    variables = default_variables
}

daq = {
    modules = {
        { name = 'pcap', mode = 'passive' }
    }
}

-- Alert 출력
alert_fast = {
    file = true,
    packet = false,
    limit = 10
}

alert_full = {
    file = true
}

output = {
    logdir = '/tmp'
}

packets = { }

stream = { }
stream_tcp = { }
stream_udp = { }
stream_icmp = { }

normalizer = { }

-- Session Statistics Inspector
session_stats = { }
