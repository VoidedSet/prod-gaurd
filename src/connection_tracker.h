#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <string>
#include <map>
#include <set>
#include <mutex>
#include <cstdint>
#include <winsock2.h>
#include <windows.h>
#include "windivert.h"

// ConnectionKey uniquely identifies a connection between the client and server.
// The key is normalized so that the client side is always 'src' and server side is always 'dst',
// regardless of packet direction.
struct ConnectionKey
{
    bool is_ipv6;
    uint8_t src_ip[16]; // Local client IP
    uint8_t dst_ip[16]; // Remote server IP
    uint16_t src_port;  // Local client port
    uint16_t dst_port;  // Remote server port (usually 443)

    bool operator<(const ConnectionKey& other) const;
};

// Represents a IP address for the IP-to-classification cache
struct IpAddress
{
    bool is_ipv6;
    uint8_t ip[16];

    bool operator<(const IpAddress& other) const;
};

struct ConnectionInfo
{
    ConnectionKey key;
    std::string hostname;
    std::string classification; // NETFLIX, YOUTUBE, CHATGPT, GITHUB, UNKNOWN
    std::string dst_ip_str;
    uint16_t dst_port;
    ULONGLONG last_seen_ms;
    bool classified_printed;
};

class ConnectionTracker
{
public:
    // Processes a packet, tracking connection state, parsing TLS SNI, and maintaining mappings.
    void ProcessPacket(
        const WINDIVERT_ADDRESS& addr,
        PWINDIVERT_IPHDR ip_hdr,
        PWINDIVERT_IPV6HDR ipv6_hdr,
        PWINDIVERT_TCPHDR tcp_hdr,
        const uint8_t* payload,
        size_t payload_len);

    // Prints all currently active connections.
    void PrintActiveConnections() const;

    // Prunes connections that have not seen traffic within the timeout period (in milliseconds).
    void PruneInactiveConnections(ULONGLONG timeout_ms);

    // Checks if a TCP connection is throttled (e.g. classified as NETFLIX)
    bool IsKeyThrottled(const ConnectionKey& key) const;

    // Checks if an IP is classified as a throttled domain
    bool IsIpThrottled(bool is_ipv6, const uint8_t* ip) const;

private:
    // Classifies a hostname into the designated target domains or UNKNOWN.
    std::string ClassifyHostname(std::string hostname) const;

    // Formats an IP address representation to string.
    std::string FormatIp(bool is_ipv6, const uint8_t* ip) const;

    // Helper to build a ConnectionKey from headers and direction.
    ConnectionKey BuildConnectionKey(
        const WINDIVERT_ADDRESS& addr,
        PWINDIVERT_IPHDR ip_hdr,
        PWINDIVERT_IPV6HDR ipv6_hdr,
        PWINDIVERT_TCPHDR tcp_hdr) const;

    mutable std::mutex mtx_;
    std::map<ConnectionKey, ConnectionInfo> connections_;
    std::map<std::string, std::set<ConnectionKey>> hostname_to_connections_;
    std::map<IpAddress, std::string> ip_to_classification_; // Dynamic IP-to-classification cache
};

#endif // CONNECTION_TRACKER_H
