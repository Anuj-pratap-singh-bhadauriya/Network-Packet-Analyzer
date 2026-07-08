// Multi-threaded DPI Engine - Fixed Version
// Architecture: Reader -> LB threads -> FP threads -> Output

#include <iostream>
#include <fstream>
#include <thread>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "npcap_loader.h"
#include <csignal>

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }

    // DLP: Add a keyword to watch for in plaintext HTTP traffic
    void addDLPKeyword(const std::string& keyword) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Store lowercase for case-insensitive matching
        std::string kw = keyword;
        std::transform(kw.begin(), kw.end(), kw.begin(), ::tolower);
        dlp_keywords_.push_back(kw);
        std::cout << "[DLP] Watching keyword: " << keyword << "\n";
    }

    // Returns which keyword was found in payload, or empty string if none
    std::string scanDLP(const uint8_t* payload, size_t len) const {
        if (dlp_keywords_.empty() || !payload || len == 0) return "";
        // Build lowercase copy of payload for case-insensitive match
        std::string text(reinterpret_cast<const char*>(payload), len);
        std::transform(text.begin(), text.end(), text.begin(), ::tolower);
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& kw : dlp_keywords_) {
            if (text.find(kw) != std::string::npos) return kw;
        }
        return "";
    }

    bool hasDLPKeywords() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return !dlp_keywords_.empty();
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
    std::vector<std::string> dlp_keywords_;   // DLP keyword list
};

// =============================================================================
// Firewall Logger (thread-safe) - Red alerts + log file
// =============================================================================
class FirewallLogger {
public:
    void open(const std::string& log_file) {
        std::lock_guard<std::mutex> lock(mutex_);
        log_.open(log_file, std::ios::out | std::ios::trunc);
        if (log_.is_open()) {
            log_ << "\n=== Firewall Session Started ===\n";
            log_.flush();
        }
    }

    void alert(const std::string& reason, const std::string& detail,
               const std::string& src_ip, const std::string& dst_ip) {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char timebuf[32];
        std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", std::localtime(&t));

        std::lock_guard<std::mutex> lock(mutex_);

        // Red color terminal alert
#ifdef _WIN32
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
#else
        std::cout << "\033[1;31m";
#endif
        std::cout << "[FIREWALL ALERT " << timebuf << "] "
                  << "🛑 BLOCKED [" << reason << ": " << detail << "] "
                  << src_ip << " -> " << dst_ip << "\n";
#ifdef _WIN32
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
        std::cout << "\033[0m";
#endif

        // Write to log file
        if (log_.is_open()) {
            log_ << "[" << timebuf << "] BLOCKED " << reason << ": " << detail
                 << " | " << src_ip << " -> " << dst_ip << "\n";
            log_.flush();
        }

        total_alerts_++;
    }

    uint64_t totalAlerts() const { return total_alerts_.load(); }

    // DLP Alert - Purple/Magenta color (different from red firewall alerts)
    void dlpAlert(const std::string& keyword, const std::string& src_ip,
                  const std::string& dst_ip, uint16_t dst_port) {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char timebuf[32];
        std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", std::localtime(&t));

        std::lock_guard<std::mutex> lock(mutex_);

        // Purple/Magenta color for DLP alerts
#ifdef _WIN32
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#else
        std::cout << "\033[1;35m";
#endif
        std::cout << "[DLP ALERT " << timebuf << "] "
                  << "\xF0\x9F\x9A\xA8 DATA LEAK DETECTED! "
                  << "Keyword: '" << keyword << "' "
                  << "in PLAINTEXT HTTP (port " << dst_port << ") "
                  << src_ip << " -> " << dst_ip << "\n";
#ifdef _WIN32
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
        std::cout << "\033[0m";
#endif

        // Write to DLP log file
        if (dlp_log_.is_open()) {
            dlp_log_ << "[" << timebuf << "] DATA LEAK | Keyword: '" << keyword
                     << "' | HTTP port " << dst_port
                     << " | " << src_ip << " -> " << dst_ip << "\n";
            dlp_log_.flush();
        }

        total_dlp_alerts_++;
    }

    uint64_t totalDLPAlerts() const { return total_dlp_alerts_.load(); }

    void openDLP(const std::string& log_file) {
        std::lock_guard<std::mutex> lock(mutex_);
        dlp_log_.open(log_file, std::ios::out | std::ios::trunc);
        if (dlp_log_.is_open()) {
            dlp_log_ << "\n=== DLP Session Started ===\n";
            dlp_log_.flush();
        }
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_.is_open()) {
            log_ << "=== Session Ended. Total Blocked: " << total_alerts_.load() << " ===\n";
            log_.close();
        }
        if (dlp_log_.is_open()) {
            dlp_log_ << "=== DLP Session Ended. Total Leaks Detected: " << total_dlp_alerts_.load() << " ===\n";
            dlp_log_.close();
        }
    }

private:
    std::mutex mutex_;
    std::ofstream log_;
    std::ofstream dlp_log_;                        // Separate DLP log file
    std::atomic<uint64_t> total_alerts_{0};
    std::atomic<uint64_t> total_dlp_alerts_{0};   // DLP alert counter
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};

    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;

    // Bandwidth tracking per-IP and per-App
    std::unordered_map<uint32_t, uint64_t> ip_bytes;   // src_ip -> total bytes
    std::unordered_map<AppType, uint64_t>  app_bytes;  // app    -> total bytes

    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }

    // Thread-safe bandwidth recorder
    void recordBandwidth(uint32_t src_ip, AppType app, uint64_t bytes) {
        std::lock_guard<std::mutex> lock(app_mutex);
        ip_bytes[src_ip]  += bytes;
        app_bytes[app]    += bytes;
    }

    // Helper: human-readable bytes string
    static std::string fmtBytes(uint64_t b) {
        char buf[32];
        if (b >= 1024ULL * 1024 * 1024)
            std::snprintf(buf, sizeof(buf), "%.2f GB", b / (1024.0 * 1024 * 1024));
        else if (b >= 1024ULL * 1024)
            std::snprintf(buf, sizeof(buf), "%.2f MB", b / (1024.0 * 1024));
        else if (b >= 1024)
            std::snprintf(buf, sizeof(buf), "%.2f KB", b / 1024.0);
        else
            std::snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
        return buf;
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue,
             FirewallLogger* fw_logger)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue),
          fw_logger_(fw_logger) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    FirewallLogger* fw_logger_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            // Check blocking
            if (!flow.blocked) {
                bool newly_blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
                if (newly_blocked && !flow.blocked) {
                    // First time this flow is being blocked - fire an alert
                    auto ipToStr = [](uint32_t ip) {
                        return std::to_string(ip & 0xFF) + "." +
                               std::to_string((ip >> 8) & 0xFF) + "." +
                               std::to_string((ip >> 16) & 0xFF) + "." +
                               std::to_string((ip >> 24) & 0xFF);
                    };
                    std::string block_reason = flow.sni.empty()
                        ? appTypeToString(flow.app_type)
                        : flow.sni;
                    if (fw_logger_) {
                        fw_logger_->alert(
                            appTypeToString(flow.app_type),
                            block_reason,
                            ipToStr(pkt.tuple.src_ip),
                            ipToStr(pkt.tuple.dst_ip)
                        );
                    }
                }
                flow.blocked = newly_blocked;
            }

            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            stats_->recordBandwidth(pkt.tuple.src_ip, flow.app_type, pkt.data.size());

            // ================================================================
            // DLP: Scan unencrypted HTTP/plaintext payload for sensitive keywords
            // Only scan HTTP (port 80) and other non-encrypted ports, NOT HTTPS
            // ================================================================
            if (rules_->hasDLPKeywords() && !flow.blocked) {
                bool is_plaintext = (pkt.tuple.dst_port == 80 ||
                                     pkt.tuple.src_port == 80 ||
                                     pkt.tuple.dst_port == 8080 ||
                                     pkt.tuple.dst_port == 21 ||   // FTP
                                     pkt.tuple.dst_port == 25 ||   // SMTP
                                     pkt.tuple.dst_port == 23);    // Telnet
                if (is_plaintext && pkt.payload_length > 0) {
                    const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
                    std::string found_kw = rules_->scanDLP(payload, pkt.payload_length);
                    if (!found_kw.empty()) {
                        auto ipToStr = [](uint32_t ip) {
                            return std::to_string(ip & 0xFF) + "." +
                                   std::to_string((ip >> 8) & 0xFF) + "." +
                                   std::to_string((ip >> 16) & 0xFF) + "." +
                                   std::to_string((ip >> 24) & 0xFF);
                        };
                        if (fw_logger_) {
                            fw_logger_->dlpAlert(
                                found_kw,
                                ipToStr(pkt.tuple.src_ip),
                                ipToStr(pkt.tuple.dst_ip),
                                pkt.tuple.dst_port
                            );
                        }
                    }
                }
            }

            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        

        
        // Port-based fallback (but don't mark as classified - might get SNI later)
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
        
        // QUIC detection: UDP port 443 = likely QUIC (HTTP/3)
        // Try QUIC SNI extraction
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = QUICSNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
            // Mark as HTTPS even if SNI not found (QUIC = encrypted HTTPS)
            flow.app_type = AppType::HTTPS;
        }
        
        // DNS domain extraction - extract domain from DNS query and classify it
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            if (pkt.payload_length > 12) {
                auto domain = DNSExtractor::extractQuery(payload, pkt.payload_length);
                if (domain && !domain->empty()) {
                    AppType dns_app = sniToAppType(*domain);
                    // Record EVERY domain we see via DNS
                    flow.sni = *domain;
                    if (dns_app == AppType::HTTPS) dns_app = AppType::DNS;
                    flow.app_type = dns_app;
                    flow.classified = true;
                    return;
                }
            }
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// Ctrl+C handler for live capture mode
// =============================================================================
static std::atomic<bool> g_live_running{true};

#ifdef _WIN32
static BOOL WINAPI liveCtrlHandler(DWORD sig) {
    if (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) {
        g_live_running = false;
        return TRUE;
    }
    return FALSE;
}
#else
static void liveSignalHandler(int) {
    g_live_running = false;
}
#endif

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
    };
    
    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;

        std::cout << "\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "|              DPI ENGINE v2.0 (Multi-threaded)                 |\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "| Load Balancers: " << std::setw(2) << cfg.num_lbs
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     |\n";
        std::cout << "+--------------------------------------------------------------+\n\n";

        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &output_queue_, &fw_logger_));
        }
        
        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    void addDLPKeyword(const std::string& kw) { rules_.addDLPKeyword(kw); }
    
    bool process(const std::string& input_file, const std::string& output_file,
                 const std::string& log_file = "firewall_alerts.log") {
        // Open firewall log
        fw_logger_.open(log_file);
        fw_logger_.openDLP("dlp_alerts.log");
        // Open input
        PcapReader reader;
        if (!reader.open(input_file)) return false;
        
        // Open output
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Cannot open output file\n";
            return false;
        }
        
        // Write PCAP header
        const auto& hdr = reader.getGlobalHeader();
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        
        // Start all threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
        
        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;
                
                PcapPacketHeader phdr;
                phdr.ts_sec = pkt_opt->ts_sec;
                phdr.ts_usec = pkt_opt->ts_usec;
                phdr.incl_len = pkt_opt->data.size();
                phdr.orig_len = pkt_opt->data.size();
                
                output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
            }
        });
        
        // Read and dispatch packets
        std::cout << "[Reader] Processing packets...\n";
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;
        
        while (reader.readNextPacket(raw)) {
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
            
            // Calculate offset BEFORE moving raw.data
            size_t p_offset = parsed.payload_data ? (parsed.payload_data - raw.data.data()) : raw.data.size();
            
            // Create packet
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);
            
            // Parse 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            
            pkt.payload_offset = p_offset;
            pkt.payload_length = parsed.payload_length;
            
            // Filter empty payloads
            if (pkt.payload_length == 0) continue;
            
            // Update stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;
            
            // Dispatch to LB (hash-based)
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }
        
        std::cout << "[Reader] Done reading " << pkt_id << " packets\n";
        reader.close();
        
        // Wait for queues to drain
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Stop all threads
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        output_running = false;
        output_queue_.shutdown();
        output_thread.join();
        
        output.close();
        fw_logger_.close();

        // Print report
        printReport();

        return true;
    }

    // =========================================================================
    // Live Capture Mode - Sniff directly from Wi-Fi adapter
    // =========================================================================
    bool processLive(int iface_idx = -1, int duration_secs = 0,
                     const std::string& save_file = "") {
        // Load Npcap DLL at runtime
        auto& pcap = Npcap::Loader::get();
        if (!pcap.load()) {
            std::cerr << "\n[ERROR] " << pcap.err() << "\n";
            return false;
        }

        // Enumerate network interfaces
        Npcap::pcap_if_t* alldevs = nullptr;
        char errbuf[256] = {};
        if (pcap.findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            std::cerr << "\n[ERROR] Cannot list interfaces: " << errbuf << "\n";
            std::cerr << "[TIP] Run as Administrator!\n";
            return false;
        }

        // Collect into vector for indexed access
        std::vector<Npcap::pcap_if_t*> devs;
        for (auto* d = alldevs; d; d = d->next) devs.push_back(d);

        // Display interface menu
        std::cout << "\n+----------------------------------------------------------+\n";
        std::cout << "|            AVAILABLE NETWORK INTERFACES                   |\n";
        std::cout << "+----------------------------------------------------------+\n";
        for (size_t i = 0; i < devs.size(); i++) {
            std::string desc = devs[i]->description ? devs[i]->description : devs[i]->name;
            std::string ip;
            for (auto* a = devs[i]->addresses; a; a = a->next) {
                auto s = Npcap::ipFromSockaddr(a->addr);
                if (!s.empty() && s != "0.0.0.0") { ip = s; break; }
            }
            std::cout << "| [" << i << "] " << std::left << std::setw(40) << desc;
            if (!ip.empty()) std::cout << " (" << ip << ")";
            std::cout << "\n";
        }
        std::cout << "+----------------------------------------------------------+\n";

        // Select interface
        int sel = iface_idx;
        if (sel < 0 || sel >= (int)devs.size()) {
            std::cout << "\nSelect interface [0-" << devs.size() - 1 << "]: ";
            std::cin >> sel;
        }
        if (sel < 0 || sel >= (int)devs.size()) {
            std::cerr << "[ERROR] Invalid selection.\n";
            pcap.freealldevs(alldevs);
            return false;
        }

        // Open interface (snaplen=65535, promiscuous=1, timeout=1000ms)
        auto* handle = pcap.open_live(devs[sel]->name, 65535, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "\n[ERROR] Cannot open interface: " << errbuf << "\n";
            std::cerr << "[TIP] Run as Administrator!\n";
            pcap.freealldevs(alldevs);
            return false;
        }

        // Verify Ethernet link type
        int linktype = pcap.datalink(handle);
        if (linktype != 1) {
            std::cerr << "[WARNING] Link type " << linktype << " (expected Ethernet).\n";
        }

        std::string iface_name = devs[sel]->description ? devs[sel]->description : devs[sel]->name;
        pcap.freealldevs(alldevs);

        // Print live capture banner
        std::cout << "\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "|               LIVE CAPTURE MODE ACTIVATED                     |\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "| Interface: " << std::left << std::setw(47) << iface_name << "|\n";
        if (duration_secs > 0) {
            std::cout << "| Duration:  " << std::setw(47) << (std::to_string(duration_secs) + " seconds") << "|\n";
        } else {
            std::cout << "| Duration:  " << std::setw(47) << "Until Ctrl+C" << "|\n";
        }
        if (!save_file.empty()) {
            std::cout << "| Saving to: " << std::setw(47) << save_file << "|\n";
        }
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "\n[LIVE] Press Ctrl+C to stop capture...\n\n";

        // Open output PCAP file if saving requested
        std::ofstream save_output;
        bool saving = false;
        if (!save_file.empty()) {
            save_output.open(save_file, std::ios::binary);
            if (save_output.is_open()) {
                PcapGlobalHeader ghdr{};
                ghdr.magic_number = 0xa1b2c3d4;
                ghdr.version_major = 2;
                ghdr.version_minor = 4;
                ghdr.thiszone = 0;
                ghdr.sigfigs = 0;
                ghdr.snaplen = 65535;
                ghdr.network = 1;
                save_output.write(reinterpret_cast<const char*>(&ghdr), sizeof(ghdr));
                saving = true;
            }
        }

        // Open firewall log
        fw_logger_.open("firewall_alerts.log");
        fw_logger_.openDLP("dlp_alerts.log");

        // Start all processing threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();

        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;
                if (saving) {
                    PcapPacketHeader phdr;
                    phdr.ts_sec = pkt_opt->ts_sec;
                    phdr.ts_usec = pkt_opt->ts_usec;
                    phdr.incl_len = pkt_opt->data.size();
                    phdr.orig_len = pkt_opt->data.size();
                    save_output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                    save_output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
                }
            }
        });

        // Install Ctrl+C handler
        g_live_running = true;
#ifdef _WIN32
        SetConsoleCtrlHandler(liveCtrlHandler, TRUE);
#else
        signal(SIGINT, liveSignalHandler);
#endif

        // ===== MAIN CAPTURE LOOP =====
        uint32_t pkt_id = 0;
        auto start_time = std::chrono::steady_clock::now();
        auto last_stats = start_time;

        while (g_live_running) {
            // Check duration limit
            if (duration_secs > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time).count();
                if (elapsed >= duration_secs) break;
            }

            // Read next packet from network adapter
            Npcap::pcap_pkthdr* phdr = nullptr;
            const uint8_t* pdata = nullptr;
            int res = pcap.next_ex(handle, &phdr, &pdata);
            if (res == 0) continue;  // Timeout
            if (res < 0) break;      // Error

            // Parse the raw Ethernet frame
            RawPacket raw;
            raw.header.ts_sec = static_cast<uint32_t>(phdr->ts.tv_sec);
            raw.header.ts_usec = static_cast<uint32_t>(phdr->ts.tv_usec);
            raw.header.incl_len = phdr->caplen;
            raw.header.orig_len = phdr->len;
            raw.data.assign(pdata, pdata + phdr->caplen);

            ParsedPacket parsed;
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

            size_t p_offset = parsed.payload_data
                ? (parsed.payload_data - raw.data.data())
                : raw.data.size();

            // Show DNS queries live (shows what sites are being browsed)
            if ((parsed.src_port == 53 || parsed.dest_port == 53) && parsed.payload_length > 12) {
                const uint8_t* payload = raw.data.data() + p_offset;
                auto domain = DNSExtractor::extractQuery(payload, parsed.payload_length);
                if (domain && !domain->empty()) {
                    auto now_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    char tbuf[16];
                    std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", std::localtime(&now_t));
#ifdef _WIN32
                    HANDLE hC = GetStdHandle(STD_OUTPUT_HANDLE);
                    SetConsoleTextAttribute(hC, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#else
                    std::cout << "\033[36m";
#endif
                    std::cout << "[DNS " << tbuf << "] \xF0\x9F\x94\x8D " << *domain << "\n";
#ifdef _WIN32
                    SetConsoleTextAttribute(hC, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
                    std::cout << "\033[0m";
#endif
                }
            }

            // Build Packet for the processing pipeline
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);

            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };

            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            pkt.payload_offset = p_offset;
            pkt.payload_length = parsed.payload_length;

            if (pkt.payload_length == 0) continue;

            // Update global stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;

            // Dispatch to Load Balancer
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));

            // Print periodic live stats every 5 seconds
            auto now = std::chrono::steady_clock::now();
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count();
            if (secs >= 5) {
                last_stats = now;
                auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
#ifdef _WIN32
                HANDLE hC = GetStdHandle(STD_OUTPUT_HANDLE);
                SetConsoleTextAttribute(hC, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#else
                std::cout << "\033[33m";
#endif
                std::cout << "--- Stats (" << total_elapsed << "s) | Pkts: "
                          << stats_.total_packets.load()
                          << " | TCP: " << stats_.tcp_packets.load()
                          << " | UDP: " << stats_.udp_packets.load()
                          << " | Blocked: " << stats_.dropped.load()
                          << " | Total: " << Stats::fmtBytes(stats_.total_bytes.load());
                // Show top bandwidth app inline
                {
                    std::lock_guard<std::mutex> lk(stats_.app_mutex);
                    uint64_t top_bytes = 0; AppType top_app = AppType::UNKNOWN;
                    for (auto& [a, b] : stats_.app_bytes) {
                        if (b > top_bytes) { top_bytes = b; top_app = a; }
                    }
                    if (top_bytes > 0)
                        std::cout << " | Top: " << appTypeToString(top_app)
                                  << " " << Stats::fmtBytes(top_bytes);
                }
                std::cout << " ---\n";
#ifdef _WIN32
                SetConsoleTextAttribute(hC, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
                std::cout << "\033[0m";
#endif
            }
        }

        // ===== CLEANUP =====
        std::cout << "\n\n[LIVE] Capture stopped. Total packets: " << pkt_id << "\n";

#ifdef _WIN32
        SetConsoleCtrlHandler(liveCtrlHandler, FALSE);
#else
        signal(SIGINT, SIG_DFL);
#endif

        pcap.close(handle);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();

        output_running = false;
        output_queue_.shutdown();
        output_thread.join();

        if (saving) save_output.close();
        fw_logger_.close();

        printReport();

        if (saving) {
            std::cout << "\nRecording saved to: " << save_file << "\n";
        }

        return true;
    }

private:
    Config config_;
    Rules rules_;
    Stats stats_;
    FirewallLogger fw_logger_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    
    void printReport() {
        std::cout << "\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "|                      PROCESSING REPORT                        |\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "| Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           |\n";
        std::cout << "| Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           |\n";
        std::cout << "| TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           |\n";
        std::cout << "| UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           |\n";
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "| Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           |\n";
        std::cout << "| Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           |\n";
        
        // Thread stats
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "| THREAD STATISTICS                                             |\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "|   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           |\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "|   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           |\n";
        }
        
        // App distribution
        std::cout << "+--------------------------------------------------------------+\n";
        std::cout << "|                   APPLICATION BREAKDOWN                       |\n";
        std::cout << "+--------------------------------------------------------------+\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');
            
            std::cout << "| " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  |\n";
        }
        
        std::cout << "+--------------------------------------------------------------+\n";

        // ============================================================
        // BANDWIDTH LEADERBOARD
        // ============================================================
        auto ipToStr = [](uint32_t ip) {
            return std::to_string(ip & 0xFF) + "." +
                   std::to_string((ip >> 8) & 0xFF) + "." +
                   std::to_string((ip >> 16) & 0xFF) + "." +
                   std::to_string((ip >> 24) & 0xFF);
        };

        // Sort app_bytes by bytes descending
        std::vector<std::pair<AppType, uint64_t>> sorted_app_bw(
            stats_.app_bytes.begin(), stats_.app_bytes.end());
        std::sort(sorted_app_bw.begin(), sorted_app_bw.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        // Sort ip_bytes by bytes descending
        std::vector<std::pair<uint32_t, uint64_t>> sorted_ip_bw(
            stats_.ip_bytes.begin(), stats_.ip_bytes.end());
        std::sort(sorted_ip_bw.begin(), sorted_ip_bw.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        if (!sorted_app_bw.empty() || !sorted_ip_bw.empty()) {
            std::cout << "\n";
#ifdef _WIN32
            HANDLE hBW = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hBW, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#else
            std::cout << "\033[1;36m";
#endif
            // App Bandwidth Leaderboard
            if (!sorted_app_bw.empty()) {
                uint64_t top_bw = sorted_app_bw[0].second;
                std::cout << "+--------------------------------------------------------------+\n";
                std::cout << "|            BANDWIDTH MONITOR - TOP APP CONSUMERS              |\n";
                std::cout << "+------+------------------+-------------+----------------------+\n";
                std::cout << "| Rank | Application      | Data Used   | Bar                  |\n";
                std::cout << "+------+------------------+-------------+----------------------+\n";
                int rank = 1;
                for (const auto& [app, bytes] : sorted_app_bw) {
                    if (rank > 8) break;
                    int bar = top_bw > 0 ? (int)(20.0 * bytes / top_bw) : 0;
                    std::string bar_str(bar, '#'); // solid block char
                    std::cout << "|  #" << rank++ << "  | "
                              << std::left << std::setw(16) << appTypeToString(app) << " | "
                              << std::right << std::setw(11) << Stats::fmtBytes(bytes) << " | "
                              << std::left << std::setw(20) << bar_str << " |\n";
                }
                std::cout << "+------+------------------+-------------+----------------------+\n";
            }

            // IP Bandwidth Leaderboard
            if (!sorted_ip_bw.empty()) {
                uint64_t top_bw = sorted_ip_bw[0].second;
                std::cout << "\n";
                std::cout << "+--------------------------------------------------------------+\n";
                std::cout << "|            BANDWIDTH MONITOR - TOP IP CONSUMERS               |\n";
                std::cout << "+------+------------------+-------------+----------------------+\n";
                std::cout << "| Rank | IP Address       | Data Used   | Bar                  |\n";
                std::cout << "+------+------------------+-------------+----------------------+\n";
                int rank = 1;
                for (const auto& [ip, bytes] : sorted_ip_bw) {
                    if (rank > 5) break;
                    int bar = top_bw > 0 ? (int)(20.0 * bytes / top_bw) : 0;
                    std::string bar_str(bar, '#');
                    std::cout << "|  #" << rank++ << "  | "
                              << std::left << std::setw(16) << ipToStr(ip) << " | "
                              << std::right << std::setw(11) << Stats::fmtBytes(bytes) << " | "
                              << std::left << std::setw(20) << bar_str << " |\n";
                }
                std::cout << "+------+------------------+-------------+----------------------+\n";
            }

#ifdef _WIN32
            SetConsoleTextAttribute(hBW, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
            std::cout << "\033[0m";
#endif
        }


        uint64_t alerts = fw_logger_.totalAlerts();
        if (alerts > 0) {
            std::cout << "\n";
#ifdef _WIN32
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
#else
            std::cout << "\033[1;31m";
#endif
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "|                   FIREWALL SUMMARY                            |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "| Total Flows Blocked: " << std::setw(12) << alerts
                      << "                           |\n";
            std::cout << "| Log saved to:        firewall_alerts.log                     |\n";
            std::cout << "+--------------------------------------------------------------+\n";
#ifdef _WIN32
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
            std::cout << "\033[0m";
#endif
        }

        // DLP summary (purple color)
        uint64_t dlp_alerts = fw_logger_.totalDLPAlerts();
        if (dlp_alerts > 0) {
            std::cout << "\n";
#ifdef _WIN32
            HANDLE hConsole2 = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole2, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#else
            std::cout << "\033[1;35m";
#endif
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "|                   DLP SUMMARY                                 |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "| Data Leaks Detected: " << std::setw(12) << dlp_alerts
                      << "                           |\n";
            std::cout << "| Log saved to:        dlp_alerts.log                         |\n";
            std::cout << "+--------------------------------------------------------------+\n";
#ifdef _WIN32
            SetConsoleTextAttribute(hConsole2, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
            std::cout << "\033[0m";
#endif
        }

        // Detected SNIs
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }
    }
};

// =============================================================================
// Main
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage (File Mode):
  )" << prog << R"( <input.pcap> <output.pcap> [options]

Usage (Live Capture Mode):
  )" << prog << R"( --live [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Live Mode Options:
  --live                 Enable live Wi-Fi capture mode
  --iface <n>            Select network interface by index
  --duration <secs>      Capture duration in seconds (0 = until Ctrl+C)
  -o <file.pcap>         Save live capture to file

Examples:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << prog << R"( --live
  )" << prog << R"( --live --block-app YouTube
  )" << prog << R"( --live -o recording.pcap --block-domain facebook.com
)";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    bool live_mode = false;
    int iface_idx = -1;
    int duration = 0;
    std::string input, output, live_output;

    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains, dlp_keywords;

    // Parse all arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--live") live_mode = true;
        else if (arg == "--iface" && i + 1 < argc) iface_idx = std::stoi(argv[++i]);
        else if (arg == "--duration" && i + 1 < argc) duration = std::stoi(argv[++i]);
        else if (arg == "-o" && i + 1 < argc) live_output = argv[++i];
        else if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--dlp-keyword" && i + 1 < argc) dlp_keywords.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--help" || arg == "-h") { printUsage(argv[0]); return 0; }
        else {
            // Positional arguments: input and output files
            if (input.empty()) input = arg;
            else if (output.empty()) output = arg;
        }
    }

    // Validate arguments
    if (!live_mode && (input.empty() || output.empty())) {
        printUsage(argv[0]);
        return 1;
    }

    DPIEngine engine(cfg);

    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    for (const auto& kw : dlp_keywords) engine.addDLPKeyword(kw);

    if (live_mode) {
        // Live Wi-Fi capture mode
        if (!engine.processLive(iface_idx, duration, live_output)) {
            return 1;
        }
    } else {
        // File processing mode (original behavior)
        if (!engine.process(input, output)) {
            return 1;
        }
        std::cout << "\nOutput written to: " << output << "\n";
    }

    return 0;
}
