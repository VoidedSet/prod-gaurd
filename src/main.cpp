#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <conio.h>
#include "windivert.h"
#include "connection_tracker.h"
#include "packet_throttler.h"

// Link required libraries for MSVC
#pragma comment(lib, "ws2_32.lib")

// Globals to signal shutdown
volatile bool g_running = true;

void KeyListenerThread(ConnectionTracker& tracker, HANDLE divert_handle)
{
    std::cout << "\n-------------------------------------------------------------\n";
    std::cout << "FocusGuard Running. Controls:\n";
    std::cout << "  [s] Print active connections map\n";
    std::cout << "  [q] Quit application cleanly\n";
    std::cout << "-------------------------------------------------------------\n\n";

    while (g_running)
    {
        if (_kbhit())
        {
            int ch = _getch();
            if (ch == 'q' || ch == 'Q')
            {
                std::cout << "\nShutdown requested. Closing interception handle...\n";
                g_running = false;
                WinDivertShutdown(divert_handle, WINDIVERT_SHUTDOWN_BOTH);
                break;
            }
            else if (ch == 's' || ch == 'S')
            {
                tracker.PrintActiveConnections();
            }
        }
        Sleep(100);
    }
}

int main()
{
    // Initialize Winsock
    WSADATA wsaData;
    int wsa_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_res != 0)
    {
        std::cerr << "Error: WSAStartup failed with error " << wsa_res << "\n";
        return 1;
    }

    // Intercept outbound/inbound TCP 443 (HTTPS) and UDP 443 (QUIC)
    const char* filter = "tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443) or udp and (udp.DstPort == 443 or udp.SrcPort == 443)";

    HANDLE handle = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_NETWORK,
        0, // Priority
        0  // Flags
    );

    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        std::cerr << "Error: Failed to open WinDivert handle (Error code " << err << ").\n";
        if (err == ERROR_ACCESS_DENIED)
        {
            std::cerr << "Please ensure you are running this application as Administrator.\n";
        }
        WSACleanup();
        return 1;
    }

    ConnectionTracker tracker;
    PacketThrottler throttler(handle);

    // Start background throttling worker
    throttler.Start();

    // Start keyboard input listener thread
    std::thread key_thread(KeyListenerThread, std::ref(tracker), handle);

    char packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    ULONGLONG last_prune_time = GetTickCount64();

    while (g_running)
    {
        PWINDIVERT_IPHDR ip_header = nullptr;
        PWINDIVERT_IPV6HDR ipv6_header = nullptr;
        PWINDIVERT_TCPHDR tcp_header = nullptr;
        PWINDIVERT_UDPHDR udp_header = nullptr;
        PVOID payload = nullptr;
        UINT payload_len = 0;

        if (!WinDivertRecv(
                handle,
                packet,
                sizeof(packet),
                &packetLen,
                &addr))
        {
            // Aborted due to handle close
            if (GetLastError() == ERROR_OPERATION_ABORTED)
            {
                break;
            }
            continue;
        }

        // Parse IP, TCP and UDP headers
        WinDivertHelperParsePacket(
            packet,
            packetLen,
            &ip_header,
            &ipv6_header,
            nullptr, // protocol
            nullptr, // icmp
            nullptr, // icmpv6
            &tcp_header,
            &udp_header,
            &payload,
            &payload_len,
            nullptr, // next
            nullptr  // next len
        );

        // --- 1. Handle UDP (QUIC) Traffic ---
        if (udp_header)
        {
            bool is_throttled = false;
            if (addr.Outbound)
            {
                if (ipv6_header)
                {
                    is_throttled = tracker.IsIpThrottled(true, reinterpret_cast<const uint8_t*>(ipv6_header->DstAddr));
                }
                else if (ip_header)
                {
                    is_throttled = tracker.IsIpThrottled(false, reinterpret_cast<const uint8_t*>(&ip_header->DstAddr));
                }
            }
            else
            {
                if (ipv6_header)
                {
                    is_throttled = tracker.IsIpThrottled(true, reinterpret_cast<const uint8_t*>(ipv6_header->SrcAddr));
                }
                else if (ip_header)
                {
                    is_throttled = tracker.IsIpThrottled(false, reinterpret_cast<const uint8_t*>(&ip_header->SrcAddr));
                }
            }

            if (is_throttled)
            {
                // Silently drop UDP packets destined for throttled services (Netflix)
                // This forces the client browser to immediately fall back to TCP 443
                continue;
            }
            else
            {
                // Fast Path (Free Way): Immediately reinject unthrottled UDP packets
                WinDivertSend(handle, packet, packetLen, nullptr, &addr);
            }
            continue;
        }

        // --- 2. Handle TCP Traffic ---
        if (tcp_header)
        {
            // Process the packet to maintain connections and update tracker mappings
            tracker.ProcessPacket(
                addr,
                ip_header,
                ipv6_header,
                tcp_header,
                static_cast<const uint8_t*>(payload),
                payload_len
            );

            // Re-build connection key to check throttle status
            ConnectionKey key = {};
            if (ipv6_header)
            {
                key.is_ipv6 = true;
                if (addr.Outbound)
                {
                    std::memcpy(key.src_ip, ipv6_header->SrcAddr, 16);
                    std::memcpy(key.dst_ip, ipv6_header->DstAddr, 16);
                    key.src_port = ntohs(tcp_header->SrcPort);
                    key.dst_port = ntohs(tcp_header->DstPort);
                }
                else
                {
                    std::memcpy(key.src_ip, ipv6_header->DstAddr, 16);
                    std::memcpy(key.dst_ip, ipv6_header->SrcAddr, 16);
                    key.src_port = ntohs(tcp_header->DstPort);
                    key.dst_port = ntohs(tcp_header->SrcPort);
                }
            }
            else if (ip_header)
            {
                key.is_ipv6 = false;
                if (addr.Outbound)
                {
                    std::memcpy(key.src_ip, &ip_header->SrcAddr, 4);
                    std::memcpy(key.dst_ip, &ip_header->DstAddr, 4);
                    key.src_port = ntohs(tcp_header->SrcPort);
                    key.dst_port = ntohs(tcp_header->DstPort);
                }
                else
                {
                    std::memcpy(key.src_ip, &ip_header->DstAddr, 4);
                    std::memcpy(key.dst_ip, &ip_header->SrcAddr, 4);
                    key.src_port = ntohs(tcp_header->DstPort);
                    key.dst_port = ntohs(tcp_header->SrcPort);
                }
            }

            if (tracker.IsKeyThrottled(key))
            {
                // Slow Path: Route packet to rate-limiting bucket asynchronously
                throttler.QueuePacket(key, reinterpret_cast<const uint8_t*>(packet), packetLen, addr);
            }
            else
            {
                // Fast Path (Free Way): Immediately reinject all unthrottled TCP packets
                WinDivertSend(handle, packet, packetLen, nullptr, &addr);
            }
        }

        // Periodically prune inactive connections (every 10 seconds)
        ULONGLONG now = GetTickCount64();
        if (now - last_prune_time > 10000)
        {
            tracker.PruneInactiveConnections(300000); // 5 min timeout
            last_prune_time = now;
        }
    }

    // Clean shutdown
    if (key_thread.joinable())
    {
        key_thread.join();
    }

    throttler.Stop();
    WinDivertClose(handle);
    WSACleanup();

    std::cout << "FocusGuard stopped successfully.\n";
    return 0;
}