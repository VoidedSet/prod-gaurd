#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <string>
#include <cstdint>

// Parses a TLS Client Hello handshake packet and returns the SNI (Server Name Indication) hostname if present.
// Returns an empty string if the packet is not a TLS Client Hello or does not contain an SNI.
std::string ParseTlsClientHelloSni(const uint8_t* payload, size_t payload_len);

#endif // PACKET_PARSER_H
