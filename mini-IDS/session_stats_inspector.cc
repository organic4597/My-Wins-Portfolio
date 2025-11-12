#include <unordered_map>
#include <string>
#include <ctime>
#include <fstream>
#include <arpa/inet.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <protocols/packet.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

using namespace snort;

#define SESSION_LOG_FILE "/tmp/session_stats.log"
#define FLUSH_INTERVAL 60

static const char* s_name = "session_stats";
static const char* s_help = "session statistics inspector";

struct SessionKey {
    uint32_t src_ip;
    uint32_t dst_ip;
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
            return hash<uint32_t>()(k.src_ip) ^
                   (hash<uint32_t>()(k.dst_ip) << 1) ^
                   (hash<uint16_t>()(k.src_port) << 2) ^
                   (hash<uint16_t>()(k.dst_port) << 3) ^
                   (hash<uint8_t>()(k.protocol) << 4);
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
        
        const ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
        if (!ip4h)
            return;
        
        SessionKey key;
        key.src_ip = ip4h->get_src();
        key.dst_ip = ip4h->get_dst();
        key.protocol = (uint8_t)p->get_ip_proto_next();
        
        if (p->ptrs.tcph) {
            key.src_port = p->ptrs.tcph->th_sport;
            key.dst_port = p->ptrs.tcph->th_dport;
        } else if (p->ptrs.udph) {
            key.src_port = p->ptrs.udph->uh_sport;
            key.dst_port = p->ptrs.udph->uh_dport;
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
        std::ofstream ofs(SESSION_LOG_FILE, std::ios::trunc);
        if (!ofs.is_open())
            return;
        
        time_t now = time(nullptr);
        
        for (const auto& pair : session_map) {
            const SessionKey& key = pair.first;
            const SessionStats& stats = pair.second;
            
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = key.src_ip;
            dst_addr.s_addr = key.dst_ip;
            
            inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);
            
            ofs << now << "|"
                << src_ip_str << ":" << ntohs(key.src_port) << "|"
                << dst_ip_str << ":" << ntohs(key.dst_port) << "|"
                << (int)key.protocol << "|"
                << stats.packet_count << "|"
                << stats.byte_count << "\n";
        }
        
        ofs.close();
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
    PROTO_BIT__ANY_IP,
    nullptr,                        // buffers
    nullptr,                        // service
    nullptr,                        // pinit
    nullptr,                        // pterm
    nullptr,                        // tinit
    nullptr,                        // tterm
    (InspectNew)ss_ctor,           // ctor
    (InspectDelFunc)ss_dtor,       // dtor
    nullptr,                        // ssn
    nullptr                         // reset
};
