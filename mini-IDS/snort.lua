---------------------------------------------------------------------------
-- Snort3 설정 파일 (Alert 출력 포함)
---------------------------------------------------------------------------

HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
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
