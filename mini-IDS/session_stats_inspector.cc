#include <unordered_map>
#include <string>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cerrno>
#include <arpa/inet.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <protocols/packet.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <protocols/icmp4.h>

using namespace snort;

#define SESSION_LOG_FILE "/tmp/session_stats.log"
#define FLUSH_INTERVAL 1

static const char* s_name = "session_stats";
static const char* s_help = "session statistics inspector";

struct SessionKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    bool operator==(const SessionKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

namespace std {
    template<>
    struct hash<SessionKey> {
        size_t operator()(const SessionKey& k) const {
            size_t h = 0;
            std::hash<std::string> hs;
            std::hash<uint16_t> h16;
            std::hash<uint8_t> h8;
            h ^= hs(k.src_ip) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
            h ^= hs(k.dst_ip) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
            h ^= (size_t)h16(k.src_port) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
            h ^= (size_t)h16(k.dst_port) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
            h ^= (size_t)h8(k.protocol) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
            return h;
        }
    };
}

struct SessionStats {
    uint64_t packet_count;
    uint64_t byte_count;
    time_t first_seen;
    time_t last_seen;
    
    SessionStats() : packet_count(0), byte_count(0), 
                     first_seen(time(nullptr)), last_seen(time(nullptr)) {}
};

static const Parameter s_params[] = {
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SessionStatsModule : public Module {
public:
    SessionStatsModule() : Module(s_name, s_help, s_params) {}
    Usage get_usage() const override { return INSPECT; }
};

class SessionStatsInspector : public Inspector {
public:
    SessionStatsInspector() : last_flush_time(time(nullptr)) {}
    
    ~SessionStatsInspector() override {
        flush_stats();
    }
    
    void eval(Packet* p) override {
        if (!p || !p->ptrs.ip_api.is_ip())
            return;

        const ip::IP4Hdr* ip4h = nullptr;
        const ip::IP6Hdr* ip6h = nullptr;
        bool is_ipv6 = false;

        if (p->ptrs.ip_api.is_ip6()) {
            ip6h = p->ptrs.ip_api.get_ip6h();
            is_ipv6 = true;
        } else {
            ip4h = p->ptrs.ip_api.get_ip4h();
        }

        int proto = (int)p->get_ip_proto_next();
        if (!ip4h && !ip6h)
            return;

        SessionKey key;
        char addrbuf[INET6_ADDRSTRLEN];

        if (ip4h) {
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = ip4h->get_src();
            dst_addr.s_addr = ip4h->get_dst();
            inet_ntop(AF_INET, &src_addr, addrbuf, INET6_ADDRSTRLEN);
            key.src_ip = addrbuf;
            inet_ntop(AF_INET, &dst_addr, addrbuf, INET6_ADDRSTRLEN);
            key.dst_ip = addrbuf;
        } else {
            const void* src6_ptr = static_cast<const void*>(ip6h->get_src());
            const void* dst6_ptr = static_cast<const void*>(ip6h->get_dst());
            inet_ntop(AF_INET6, src6_ptr, addrbuf, INET6_ADDRSTRLEN);
            key.src_ip = addrbuf;
            inet_ntop(AF_INET6, dst6_ptr, addrbuf, INET6_ADDRSTRLEN);
            key.dst_ip = addrbuf;
        }

        key.protocol = (uint8_t)p->get_ip_proto_next();

        if (p->ptrs.tcph) {
            key.src_port = p->ptrs.tcph->th_sport;
            key.dst_port = p->ptrs.tcph->th_dport;
        } else if (p->ptrs.udph) {
            key.src_port = p->ptrs.udph->uh_sport;
            key.dst_port = p->ptrs.udph->uh_dport;
        } else if (key.protocol == 1 || key.protocol == 58) {
            key.src_port = 0;
            key.dst_port = 0;
        } else {
            key.src_port = 0;
            key.dst_port = 0;
        }
        
        auto& stats = session_map[key];
        stats.packet_count++;
        stats.byte_count += p->pktlen;
        stats.last_seen = time(nullptr);
        
        time_t now = time(nullptr);
        if (now - last_flush_time >= FLUSH_INTERVAL) {
            flush_stats();
            last_flush_time = now;
        }
    }
    
    void show(const SnortConfig*) const override {}

private:
    std::unordered_map<SessionKey, SessionStats> session_map;
    time_t last_flush_time;
    
    void flush_stats() {
        if (session_map.empty()) {
            return;
        }
        
        std::ifstream check_file(SESSION_LOG_FILE);
        if (!check_file.good()) {
            std::ofstream create_file(SESSION_LOG_FILE, std::ios::out);
            if (create_file.is_open()) {
                create_file.close();
            }
        }
        
        std::ofstream ofs(SESSION_LOG_FILE, std::ios::app);
        if (!ofs.is_open()) {
            fprintf(stderr, "[session_stats] ERROR: Cannot open %s for writing (errno=%d: %s)\n", 
                    SESSION_LOG_FILE, errno, strerror(errno));
            return;
        }
        
        time_t now = time(nullptr);
        int count = 0;
        
        for (const auto& pair : session_map) {
            const SessionKey& key = pair.first;
            const SessionStats& stats = pair.second;
            
            ofs << now << "|"
                << key.src_ip;
            if (key.protocol != 1 && key.protocol != 58) {
                ofs << ":" << ntohs(key.src_port);
            }
            ofs << "|"
                << key.dst_ip;
            if (key.protocol != 1 && key.protocol != 58) {
                ofs << ":" << ntohs(key.dst_port);
            }
            ofs << "|"
                << (int)key.protocol << "|"
                << stats.packet_count << "|"
                << stats.byte_count << "\n";
            count++;
        }
        
        ofs.close();
        if (count > 0) {
            int icmp_count = std::count_if(session_map.begin(), session_map.end(), 
                                          [](const auto& p) { return p.first.protocol == 1 || p.first.protocol == 58; });
            int udp_count = std::count_if(session_map.begin(), session_map.end(), 
                                         [](const auto& p) { return p.first.protocol == 17; });
            int tcp_count = std::count_if(session_map.begin(), session_map.end(), 
                                         [](const auto& p) { return p.first.protocol == 6; });
            
            if (icmp_count > 0 || udp_count > 0) {
                fprintf(stderr, "[session_stats] Flushed %d sessions: ICMP=%d, UDP=%d, TCP=%d\n", 
                        count, icmp_count, udp_count, tcp_count);
            }
        }
        session_map.clear();
    }
};

static Module* mod_ctor() { return new SessionStatsModule; }
static void mod_dtor(Module* m) { delete m; }
static Inspector* ss_ctor(Module*) { return new SessionStatsInspector; }
static void ss_dtor(Inspector* p) { delete p; }


static const InspectApi ss_api = {
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,
    (PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__ICMP),
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    (InspectNew)ss_ctor,
    (InspectDelFunc)ss_dtor,
    nullptr,
    nullptr
};

extern "C" {
    SO_PUBLIC const BaseApi* snort_plugins[] = {
        &ss_api.base,
        nullptr
    };
}
