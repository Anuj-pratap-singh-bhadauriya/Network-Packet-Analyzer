// =============================================================================
// Npcap Runtime Dynamic Loader
// Loads wpcap.dll at runtime - no Npcap SDK installation needed
// Only requires Npcap drivers to be installed (bundled with Wireshark)
// =============================================================================

#ifndef NPCAP_LOADER_H
#define NPCAP_LOADER_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include <string>
#include <cstdint>
#include <cstdio>

namespace Npcap {

// Opaque pcap handle
typedef void pcap_t;

// Address entry in linked list (matches Npcap binary layout)
struct pcap_addr {
    pcap_addr* next;
    sockaddr*  addr;
    sockaddr*  netmask;
    sockaddr*  broadaddr;
    sockaddr*  dstaddr;
};

// Network interface entry in linked list
struct pcap_if_t {
    pcap_if_t* next;
    char*      name;
    char*      description;
    pcap_addr* addresses;
    uint32_t   flags;
};

// Packet header returned by pcap_next_ex
struct pcap_pkthdr {
    struct timeval ts;      // Timestamp (2 x long = 8 bytes on Windows)
    uint32_t      caplen;  // Captured length
    uint32_t      len;     // Original length on wire
};

// Function pointer types for pcap API
using FN_findalldevs = int     (*)(pcap_if_t**, char*);
using FN_freealldevs = void    (*)(pcap_if_t*);
using FN_open_live   = pcap_t* (*)(const char*, int, int, int, char*);
using FN_next_ex     = int     (*)(pcap_t*, pcap_pkthdr**, const uint8_t**);
using FN_close       = void    (*)(pcap_t*);
using FN_datalink    = int     (*)(pcap_t*);
using FN_geterr      = char*   (*)(pcap_t*);

// =============================================================================
// Singleton DLL Loader
// Usage:
//   auto& pcap = Npcap::Loader::get();
//   if (!pcap.load()) { /* error */ }
//   pcap.findalldevs(&alldevs, errbuf);
// =============================================================================
class Loader {
public:
    static Loader& get() {
        static Loader inst;
        return inst;
    }

    bool load() {
        if (loaded_) return true;
#ifdef _WIN32
        // Point DLL search path to Npcap directory
        SetDllDirectoryA("C:\\Windows\\System32\\Npcap");
        hLib_ = LoadLibraryA("wpcap.dll");
        if (!hLib_) {
            // Fallback: try default search path (WinPcap compat mode)
            SetDllDirectoryA(nullptr);
            hLib_ = LoadLibraryA("wpcap.dll");
        }
        if (!hLib_) {
            err_ = "Cannot load wpcap.dll. Is Npcap installed? (https://npcap.com)";
            return false;
        }

        // Resolve all function pointers from DLL
        #define RESOLVE(fn) \
            fn = reinterpret_cast<FN_##fn>(GetProcAddress(hLib_, "pcap_" #fn)); \
            if (!fn) { err_ = std::string("pcap_") + #fn + " not found"; return false; }

        RESOLVE(findalldevs)
        RESOLVE(freealldevs)
        RESOLVE(open_live)
        RESOLVE(next_ex)
        RESOLVE(close)
        RESOLVE(datalink)
        RESOLVE(geterr)

        #undef RESOLVE
#endif
        loaded_ = true;
        return true;
    }

    bool ok()                const { return loaded_; }
    const std::string& err() const { return err_;    }

    // Public function pointers (call after load())
    FN_findalldevs findalldevs = nullptr;
    FN_freealldevs freealldevs = nullptr;
    FN_open_live   open_live   = nullptr;
    FN_next_ex     next_ex     = nullptr;
    FN_close       close       = nullptr;
    FN_datalink    datalink    = nullptr;
    FN_geterr      geterr      = nullptr;

private:
    Loader() = default;
    ~Loader() {
#ifdef _WIN32
        if (hLib_) FreeLibrary(hLib_);
#endif
    }
    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;

    bool loaded_ = false;
    std::string err_;
#ifdef _WIN32
    HMODULE hLib_ = nullptr;
#endif
};

// Helper: extract IP address string from a sockaddr pointer
inline std::string ipFromSockaddr(sockaddr* sa) {
    if (!sa || sa->sa_family != AF_INET) return "";
    auto* sin = reinterpret_cast<sockaddr_in*>(sa);
    uint32_t a = sin->sin_addr.s_addr;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF);
    return buf;
}

} // namespace Npcap

#endif // NPCAP_LOADER_H
