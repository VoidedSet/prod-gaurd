#include <iostream>
#include <winsock2.h>
// #include <ws2tcpip.h>
#include <windows.h>
#include "windivert.h"

int main()
{
    HANDLE handle = WinDivertOpen(
        "outbound and tcp.DstPort == 443",
        WINDIVERT_LAYER_NETWORK,
        0,
        0);

    if (handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed: " << GetLastError() << '\n';
        return 1;
    }

    std::cout << "Monitoring outbound TCP traffic...\n";

    char packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;

    while (true)
    {
        PWINDIVERT_IPHDR ip_header = nullptr;
        PWINDIVERT_TCPHDR tcp_header = nullptr;

        if (!WinDivertRecv(
                handle,
                packet,
                sizeof(packet),
                &packetLen,
                &addr))
        {
            continue;
        }

        WinDivertHelperParsePacket(
            packet,
            packetLen,
            &ip_header,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &tcp_header,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (ip_header && tcp_header)
        {
            if (tcp_header->Syn && !tcp_header->Ack)
            {
                IN_ADDR dstAddr;
                dstAddr.S_un.S_addr = ip_header->DstAddr;

                char *ipStr = inet_ntoa(dstAddr);

                if (ipStr)
                {
                    std::cout
                        << "NEW TCP -> "
                        << ipStr
                        << ":"
                        << ntohs(tcp_header->DstPort)
                        << '\n';
                }

                Sleep(3000);
            }
        }

        WinDivertSend(
            handle,
            packet,
            packetLen,
            nullptr,
            &addr);
    }

    WinDivertClose(handle);
    return 0;
}