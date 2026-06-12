#include "packet_parser.h"
#include <vector>
#include <iostream>

std::string ParseTlsClientHelloSni(const uint8_t* data, size_t len)
{
    if (len < 5)
    {
        return "";
    }

    // TLS Record Header:
    // 0: Content Type (1 byte) -> 0x16 (Handshake)
    // 1-2: Version (2 bytes)
    // 3-4: Length (2 bytes)
    if (data[0] != 0x16)
    {
        return "";
    }

    // We can extract the record length, but since we are looking for the SNI,
    // we will parse as much of the payload as we have, matching up to 'len'.
    size_t offset = 5;

    // Handshake Protocol Header:
    // 0: Handshake Type (1 byte) -> 0x01 (Client Hello)
    // 1-3: Length (3 bytes)
    if (offset + 4 > len)
    {
        return "";
    }
    if (data[offset] != 0x01)
    {
        return "";
    }
    offset += 4; // Skip Handshake Type and Length

    // Client Hello:
    // 0-1: Version (2 bytes) -> e.g. 0x03 0x03 (TLS 1.2)
    // 2-33: Random (32 bytes)
    if (offset + 34 > len)
    {
        return "";
    }
    offset += 34; // Skip Version and Random

    // Session ID:
    // 0: Session ID Length (1 byte)
    // 1...: Session ID
    if (offset + 1 > len)
    {
        return "";
    }
    uint8_t session_id_len = data[offset];
    offset += 1;
    if (offset + session_id_len > len)
    {
        return "";
    }
    offset += session_id_len; // Skip Session ID

    // Cipher Suites:
    // 0-1: Cipher Suites Length (2 bytes)
    // 2...: Cipher Suites
    if (offset + 2 > len)
    {
        return "";
    }
    uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + cipher_suites_len > len)
    {
        return "";
    }
    offset += cipher_suites_len; // Skip Cipher Suites

    // Compression Methods:
    // 0: Compression Methods Length (1 byte)
    // 1...: Compression Methods
    if (offset + 1 > len)
    {
        return "";
    }
    uint8_t compression_methods_len = data[offset];
    offset += 1;
    if (offset + compression_methods_len > len)
    {
        return "";
    }
    offset += compression_methods_len; // Skip Compression Methods

    // Extensions:
    // 0-1: Extensions Length (2 bytes)
    // 2...: Extensions
    if (offset + 2 > len)
    {
        return "";
    }
    uint16_t extensions_length = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    size_t ext_end = offset + extensions_length;
    if (ext_end > len)
    {
        ext_end = len;
    }

    while (offset + 4 <= ext_end)
    {
        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_len > ext_end)
        {
            break;
        }

        if (ext_type == 0x0000) // Server Name Indication (SNI)
        {
            if (offset + 2 > ext_end)
            {
                break;
            }
            uint16_t sni_list_len = (data[offset] << 8) | data[offset + 1];
            size_t sni_offset = offset + 2;
            size_t sni_end = sni_offset + sni_list_len;
            if (sni_end > offset + ext_len)
            {
                sni_end = offset + ext_len;
            }

            while (sni_offset + 3 <= sni_end)
            {
                uint8_t name_type = data[sni_offset];
                uint16_t name_len = (data[sni_offset + 1] << 8) | data[sni_offset + 2];
                sni_offset += 3;

                if (sni_offset + name_len > sni_end)
                {
                    break;
                }

                if (name_type == 0x00) // Host Name
                {
                    return std::string(reinterpret_cast<const char*>(&data[sni_offset]), name_len);
                }
                sni_offset += name_len;
            }
        }
        offset += ext_len;
    }

    return "";
}
