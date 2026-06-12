#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "connection_tracker.h"
#include "packet_parser.h"
#include "schedule.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <string_view>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

ConnectionTracker::ConnectionTracker()
    : blocked_attempts_(0)
{
    LoadCache();
}

bool ConnectionKey::operator<(const ConnectionKey &other) const
{
    if (is_ipv6 != other.is_ipv6)
    {
        return is_ipv6 < other.is_ipv6;
    }
    if (src_port != other.src_port)
    {
        return src_port < other.src_port;
    }
    if (dst_port != other.dst_port)
    {
        return dst_port < other.dst_port;
    }
    int cmp_src = std::memcmp(src_ip, other.src_ip, 16);
    if (cmp_src != 0)
    {
        return cmp_src < 0;
    }
    return std::memcmp(dst_ip, other.dst_ip, 16) < 0;
}

bool IpAddress::operator<(const IpAddress &other) const
{
    if (is_ipv6 != other.is_ipv6)
    {
        return is_ipv6 < other.is_ipv6;
    }
    return std::memcmp(ip, other.ip, 16) < 0;
}

static bool EndsWith(std::string_view str, std::string_view suffix)
{
    if (str.length() < suffix.length())
    {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

static bool IsStreamingClassification(const std::string& classification)
{
    return classification == "NETFLIX" ||
           classification == "PRIMEVIDEO" ||
           classification == "DISNEYPLUS" ||
           classification == "HOTSTAR" ||
           classification == "HIANIME";
}

std::string ConnectionTracker::ClassifyHostname(std::string hostname) const
{
    // Convert to lowercase
    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });

    // Netflix & fast.com
    if (EndsWith(hostname, "netflix.com") || EndsWith(hostname, "netflix.net") ||
        EndsWith(hostname, "nflxext.com") || EndsWith(hostname, "nflximg.net") ||
        EndsWith(hostname, "nflxvideo.net") || EndsWith(hostname, "nflxso.net") ||
        EndsWith(hostname, "fast.com"))
    {
        return "NETFLIX";
    }

    // Prime Video
    if (EndsWith(hostname, "primevideo.com") || EndsWith(hostname, "pv-cdn.net") ||
        EndsWith(hostname, "amazonvideo.com") || EndsWith(hostname, "media-amazon.com"))
    {
        return "PRIMEVIDEO";
    }

    // Disney+
    if (EndsWith(hostname, "disneyplus.com") || EndsWith(hostname, "dssott.com"))
    {
        return "DISNEYPLUS";
    }

    // Hotstar
    if (EndsWith(hostname, "hotstar.com") || EndsWith(hostname, "hotstar-cdn.net"))
    {
        return "HOTSTAR";
    }

    // HiAnime
    if (EndsWith(hostname, "hianime.to") || EndsWith(hostname, "hianime.nz") ||
        EndsWith(hostname, "hianime.sx") || EndsWith(hostname, "hianime.mn") ||
        EndsWith(hostname, "hianime.ru"))
    {
        return "HIANIME";
    }

    // YouTube
    if (EndsWith(hostname, "youtube.com") || EndsWith(hostname, "youtu.be") ||
        EndsWith(hostname, "ytimg.com") || EndsWith(hostname, "ggpht.com") ||
        EndsWith(hostname, "googlevideo.com") || EndsWith(hostname, "youtube-nocookie.com"))
    {
        return "YOUTUBE";
    }

    // ChatGPT
    if (EndsWith(hostname, "chatgpt.com") || EndsWith(hostname, "openai.com"))
    {
        return "CHATGPT";
    }

    // GitHub
    if (EndsWith(hostname, "github.com") || EndsWith(hostname, "githubusercontent.com") ||
        EndsWith(hostname, "github.io") || EndsWith(hostname, "github.blog"))
    {
        return "GITHUB";
    }

    return "UNKNOWN";
}

std::string ConnectionTracker::FormatIp(bool is_ipv6, const uint8_t *ip) const
{
    char buffer[INET6_ADDRSTRLEN] = {0};
    if (is_ipv6)
    {
        inet_ntop(AF_INET6, const_cast<uint8_t *>(ip), buffer, sizeof(buffer));
        return std::string("[") + buffer + "]";
    }
    else
    {
        inet_ntop(AF_INET, const_cast<uint8_t *>(ip), buffer, sizeof(buffer));
        return buffer;
    }
}

ConnectionKey ConnectionTracker::BuildConnectionKey(
    const WINDIVERT_ADDRESS &addr,
    PWINDIVERT_IPHDR ip_hdr,
    PWINDIVERT_IPV6HDR ipv6_hdr,
    PWINDIVERT_TCPHDR tcp_hdr) const
{
    ConnectionKey key = {};
    if (ipv6_hdr)
    {
        key.is_ipv6 = true;
        if (addr.Outbound)
        {
            std::memcpy(key.src_ip, ipv6_hdr->SrcAddr, 16);
            std::memcpy(key.dst_ip, ipv6_hdr->DstAddr, 16);
            key.src_port = ntohs(tcp_hdr->SrcPort);
            key.dst_port = ntohs(tcp_hdr->DstPort);
        }
        else
        {
            std::memcpy(key.src_ip, ipv6_hdr->DstAddr, 16);
            std::memcpy(key.dst_ip, ipv6_hdr->SrcAddr, 16);
            key.src_port = ntohs(tcp_hdr->DstPort);
            key.dst_port = ntohs(tcp_hdr->SrcPort);
        }
    }
    else if (ip_hdr)
    {
        key.is_ipv6 = false;
        if (addr.Outbound)
        {
            std::memcpy(key.src_ip, &ip_hdr->SrcAddr, 4);
            std::memcpy(key.dst_ip, &ip_hdr->DstAddr, 4);
            key.src_port = ntohs(tcp_hdr->SrcPort);
            key.dst_port = ntohs(tcp_hdr->DstPort);
        }
        else
        {
            std::memcpy(key.src_ip, &ip_hdr->DstAddr, 4);
            std::memcpy(key.dst_ip, &ip_hdr->SrcAddr, 4);
            key.src_port = ntohs(tcp_hdr->DstPort);
            key.dst_port = ntohs(tcp_hdr->SrcPort);
        }
    }
    return key;
}

void ConnectionTracker::ProcessPacket(
    const WINDIVERT_ADDRESS &addr,
    PWINDIVERT_IPHDR ip_hdr,
    PWINDIVERT_IPV6HDR ipv6_hdr,
    PWINDIVERT_TCPHDR tcp_hdr,
    const uint8_t *payload,
    size_t payload_len)
{
    if (!ip_hdr && !ipv6_hdr)
    {
        return;
    }
    if (!tcp_hdr)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mtx_);

    ConnectionKey key = BuildConnectionKey(addr, ip_hdr, ipv6_hdr, tcp_hdr);
    ULONGLONG current_time = GetTickCount64();

    auto it = connections_.find(key);
    if (it == connections_.end())
    {
        // Ignore termination packets for non-tracked connections
        if (tcp_hdr->Fin || tcp_hdr->Rst)
        {
            return;
        }

        ConnectionInfo info = {};
        info.key = key;
        info.dst_ip_str = FormatIp(key.is_ipv6, key.dst_ip);
        info.dst_port = key.dst_port;
        info.last_seen_ms = current_time;
        info.classified_printed = false;

        // Check cache to classify at SYN packet
        IpAddress dst_ip = {};
        dst_ip.is_ipv6 = key.is_ipv6;
        std::memcpy(dst_ip.ip, key.dst_ip, 16);

        auto cache_it = ip_to_classification_.find(dst_ip);
        if (cache_it != ip_to_classification_.end())
        {
            info.classification = cache_it->second;
            info.hostname = "Cached (" + info.classification + ")";
            info.classified_printed = true;

            std::cout << "[" << info.classification << "] " << info.dst_ip_str << ":" << info.dst_port << "\n";

            hostname_to_connections_[info.classification].insert(key);

            // Count blocked attempt if connection matches any streaming site during focus hours
            if (IsStreamingClassification(info.classification) && tcp_hdr->Syn && !tcp_hdr->Ack && IsInFocusHours())
            {
                blocked_attempts_++;
            }
        }

        connections_[key] = info;
        it = connections_.find(key);
    }
    else
    {
        it->second.last_seen_ms = current_time;
    }

    // Process termination flags (FIN/RST)
    if (tcp_hdr->Fin || tcp_hdr->Rst)
    {
        if (it->second.classified_printed)
        {
            hostname_to_connections_[it->second.classification].erase(key);
            if (hostname_to_connections_[it->second.classification].empty())
            {
                hostname_to_connections_.erase(it->second.classification);
            }
        }
        connections_.erase(it);
        return;
    }

    // Parse SNI from Client Hello
    if (!it->second.classified_printed && payload && payload_len > 0 && addr.Outbound)
    {
        std::string hostname = ParseTlsClientHelloSni(payload, payload_len);
        if (!hostname.empty())
        {
            std::string classification = ClassifyHostname(hostname);
            it->second.hostname = hostname;
            it->second.classification = classification;
            it->second.classified_printed = true;

            std::cout << "[" << classification << "] " << it->second.dst_ip_str << ":" << it->second.dst_port << "\n";

            // Add to dynamic IP classification cache
            IpAddress dst_ip = {};
            dst_ip.is_ipv6 = key.is_ipv6;
            std::memcpy(dst_ip.ip, key.dst_ip, 16);
            ip_to_classification_[dst_ip] = classification;

            SaveCache(); // Persist immediately to file

            // Count blocked attempt for first-time SNI classification
            if (IsStreamingClassification(classification) && IsInFocusHours())
            {
                blocked_attempts_++;
            }

            // Add to active mapping
            hostname_to_connections_[classification].insert(key);
        }
    }
}

void ConnectionTracker::PrintActiveConnections() const
{
    std::lock_guard<std::mutex> lock(mtx_);
    std::cout << "\n=============================================\n";
    std::cout << "FocusGuard - Active Connections Map\n";
    std::cout << "=============================================\n";

    if (hostname_to_connections_.empty())
    {
        std::cout << "(No active classified connections)\n";
    }
    else
    {
        for (const auto &pair : hostname_to_connections_)
        {
            const std::string &category = pair.first;
            const std::set<ConnectionKey> &conn_set = pair.second;
            std::cout << category << " (" << conn_set.size() << " active connection(s)):\n";
            for (const auto &key : conn_set)
            {
                auto it = connections_.find(key);
                if (it != connections_.end())
                {
                    std::cout << "  - " << it->second.dst_ip_str << ":" << it->second.dst_port
                              << " [Hostname: " << it->second.hostname << "]\n";
                }
            }
        }
    }
    std::cout << "=============================================\n\n";
}

void ConnectionTracker::PruneInactiveConnections(ULONGLONG timeout_ms)
{
    std::lock_guard<std::mutex> lock(mtx_);
    ULONGLONG current_time = GetTickCount64();

    for (auto it = connections_.begin(); it != connections_.end();)
    {
        if (current_time - it->second.last_seen_ms > timeout_ms)
        {
            if (it->second.classified_printed)
            {
                hostname_to_connections_[it->second.classification].erase(it->first);
                if (hostname_to_connections_[it->second.classification].empty())
                {
                    hostname_to_connections_.erase(it->second.classification);
                }
            }
            it = connections_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

bool ConnectionTracker::IsKeyThrottled(const ConnectionKey& key) const
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = connections_.find(key);
    if (it != connections_.end())
    {
        return IsStreamingClassification(it->second.classification);
    }

    // Check classification cache for server IP
    IpAddress dst_ip = {};
    dst_ip.is_ipv6 = key.is_ipv6;
    std::memcpy(dst_ip.ip, key.dst_ip, 16);
    auto cache_it = ip_to_classification_.find(dst_ip);
    if (cache_it != ip_to_classification_.end())
    {
        return IsStreamingClassification(cache_it->second);
    }

    return false;
}

bool ConnectionTracker::IsIpThrottled(bool is_ipv6, const uint8_t* ip) const
{
    std::lock_guard<std::mutex> lock(mtx_);
    IpAddress dst_ip = {};
    dst_ip.is_ipv6 = is_ipv6;
    std::memcpy(dst_ip.ip, ip, 16);
    auto cache_it = ip_to_classification_.find(dst_ip);
    if (cache_it != ip_to_classification_.end())
    {
        return IsStreamingClassification(cache_it->second);
    }
    return false;
}

void ConnectionTracker::LoadCache()
{
    std::ifstream file("focusguard_cache.txt");
    if (!file.is_open())
    {
        return;
    }

    std::string ip_str, classification;
    while (file >> ip_str >> classification)
    {
        IpAddress ip_addr = {};
        if (ip_str.find(':') != std::string::npos)
        {
            ip_addr.is_ipv6 = true;
            if (inet_pton(AF_INET6, ip_str.c_str(), ip_addr.ip) != 1)
            {
                continue;
            }
        }
        else
        {
            ip_addr.is_ipv6 = false;
            if (inet_pton(AF_INET, ip_str.c_str(), ip_addr.ip) != 1)
            {
                continue;
            }
        }
        ip_to_classification_[ip_addr] = classification;
    }
}

void ConnectionTracker::SaveCache() const
{
    std::ofstream file("focusguard_cache.txt");
    if (!file.is_open())
    {
        return;
    }

    for (const auto& pair : ip_to_classification_)
    {
        const IpAddress& ip_addr = pair.first;
        const std::string& classification = pair.second;

        char buffer[INET6_ADDRSTRLEN] = { 0 };
        if (ip_addr.is_ipv6)
        {
            inet_ntop(AF_INET6, const_cast<uint8_t*>(ip_addr.ip), buffer, sizeof(buffer));
        }
        else
        {
            inet_ntop(AF_INET, const_cast<uint8_t*>(ip_addr.ip), buffer, sizeof(buffer));
        }
        file << buffer << " " << classification << "\n";
    }
}

uint64_t ConnectionTracker::GetBlockedAttempts() const
{
    std::lock_guard<std::mutex> lock(mtx_);
    return blocked_attempts_;
}

