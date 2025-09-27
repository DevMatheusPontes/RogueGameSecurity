#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <stdexcept>

namespace rgs::modules::network {

// Header: 1 byte version, 1 byte service, 1 byte type, 1 byte flags, 4 bytes size (LE)
constexpr std::size_t PROTOCOL_HEADER_SIZE = 8;
constexpr std::size_t PROTOCOL_MAX_PAYLOAD = 256 * 1024; // 256KB

enum class ServiceCode : uint8_t {
    Unknown   = 0,
    Hello     = 1,
    Data      = 2,
    Heartbeat = 3
};

enum class MessageType : uint8_t {
    Unknown   = 0,
    Request   = 1,
    Response  = 2,
    Event     = 3
};

struct ProtocolHeader {
    uint8_t  version; // v1
    uint8_t  service; // ServiceCode
    uint8_t  type;    // MessageType
    uint8_t  flags;   // reservado p/ criptografia/compressão
    uint32_t size;    // payload length (LE)
};

class Protocol {
public:
    // Serializa header + payload
    static std::vector<uint8_t> serialize(const ProtocolHeader& hdr, const std::vector<uint8_t>& payload);

    // Desserializa e valida header; retorna header e payload
    static std::pair<ProtocolHeader, std::vector<uint8_t>> deserialize(const std::vector<uint8_t>& buffer);

    // Utilidades endianness
    static void writeLE32(uint8_t* out, uint32_t v);
    static uint32_t readLE32(const uint8_t* in);
};

} // namespace rgs::modules::network