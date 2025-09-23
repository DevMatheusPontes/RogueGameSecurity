#pragma once

#include <cstdint>
#include <vector>

namespace rgs::sdk::network {

    // Protocol constants
    constexpr uint32_t MAGIC_VALUE = 0xRGSSEC;
    constexpr uint16_t PROTOCOL_VERSION = 1;

    // Message types
    enum class MessageType : uint16_t {
        // Control messages
        Handshake,
        HandshakeResponse,
        Heartbeat,
        HeartbeatResponse,
        Disconnect,

        // Data messages
        Telemetry,
        Command,
        PolicyUpdate,

        // Keep last
        Count
    };

    // Flags for the protocol header
    enum class MessageFlags : uint16_t {
        None = 0,
        Encrypted = 1 << 0,
        Compressed = 1 << 1,
        HighPriority = 1 << 2,
        HasHmac = 1 << 3,
    };

    #pragma pack(push, 1)
    struct ProtocolHeader {
        uint32_t magic;
        uint16_t version;
        MessageType type;
        MessageFlags flags;
        uint32_t length; // Length of the payload
        uint64_t nonce;
        uint32_t crc32;
    };
    #pragma pack(pop)

    /**
     * @brief Validates the protocol header.
     * @param header The header to validate.
     * @return True if the header is valid, false otherwise.
     */
    inline bool validateHeader(const ProtocolHeader& header) {
        return header.magic == MAGIC_VALUE && header.version == PROTOCOL_VERSION;
    }

} // namespace rgs::sdk::network