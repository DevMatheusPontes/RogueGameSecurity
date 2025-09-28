#pragma once

#include <cstdint>
#include <array>
#include <string_view>

namespace rgs::network {

constexpr std::size_t PROTOCOL_HEADER_SIZE = 20;

struct ProtocolHeader {
    uint8_t  version;
    uint8_t  flags;
    uint16_t serviceCode;
    uint16_t messageType;
    uint32_t correlationId;
    uint32_t payloadLength;
    uint32_t reserved;

    static ProtocolHeader parse(const std::array<uint8_t, PROTOCOL_HEADER_SIZE>& raw);
    static std::array<uint8_t, PROTOCOL_HEADER_SIZE> build(const ProtocolHeader& header);
};

bool validateHeader(const ProtocolHeader& header);

}