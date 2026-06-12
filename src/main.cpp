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

// Link required libraries for MSVC
#pragma comment(lib, "ws2_32.lib")

// Globals to signal shutdown
volatile bool g_running = true;

void KeyListenerThread(ConnectionTracker& tracker, HANDLE divert_handle)
{
    std::cout << "\n-------------------------------------------------------------\n";
    std::cout << "FocusGuard Classifier Running. Controls:\n";
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
                // Closing or shutting down the handle breaks the blocking WinDivertRecv call
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
    // Initialize Winsock (required for inet_ntop and other socket functions)
    WSADATA wsaData;
    int wsa_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_res != 0)
    {
        std::cerr << "Error: WSAStartup failed with error " << wsa_res << "\n";
        return 1;
    }

    // Intercept both outbound and inbound TCP traffic on port 443 (HTTPS)
    const char* filter = "tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443)";

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

    // Start key listener thread
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
        PVOID payload = nullptr;
        UINT payload_len = 0;

        if (!WinDivertRecv(
                handle,
                packet,
                sizeof(packet),
                &packetLen,
                &addr))
        {
            // If the handle was closed or shutdown, break the loop
            if (GetLastError() == ERROR_OPERATION_ABORTED)
            {
                break;
            }
            continue;
        }

        // Parse IP and TCP headers
        WinDivertHelperParsePacket(
            packet,
            packetLen,
            &ip_header,
            &ipv6_header,
            nullptr, // protocol
            nullptr, // icmp
            nullptr, // icmpv6
            &tcp_header,
            nullptr, // udp
            &payload,
            &payload_len,
            nullptr, // next
            nullptr  // next len
        );

        if (tcp_header)
        {
            tracker.ProcessPacket(
                addr,
                ip_header,
                ipv6_header,
                tcp_header,
                static_cast<const uint8_t*>(payload),
                payload_len
            );
        }

        // Reinject the packet
        WinDivertSend(
            handle,
            packet,
            packetLen,
            nullptr,
            &addr
        );

        // Periodically prune inactive connections (every 10 seconds)
        ULONGLONG now = GetTickCount64();
        if (now - last_prune_time > 10000)
        {
            // Prune connections that haven't seen packets in 5 minutes (300000 ms)
            tracker.PruneInactiveConnections(300000);
            last_prune_time = now;
        }
    }

    // Clean shutdown
    if (key_thread.joinable())
    {
        key_thread.join();
    }

    WinDivertClose(handle);
    WSACleanup();

    std::cout << "FocusGuard stopped successfully.\n";
    return 0;
}