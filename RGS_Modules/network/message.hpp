#pragma once

#include <vector>
#include <cstdint>
#include <string_view>
#include "protocol.hpp"

namespace rgs::network {

// Representa uma mensagem completa (header + payload)
class Message {
public:
    Message() = default;
    Message(std::uint16_t service, std::uint16_t flags, std::vector<std::uint8_t> payload);

    const ProtocolHeader& header() const { return header_; }
    const std::vector<std::uint8_t>& payload() const { return payload_; }

    // Serializa para buffer (header + payload)
    std::vector<std::uint8_t> to_bytes() const;

    // Desserializa de buffer
    static std::optional<Message> from_bytes(const std::uint8_t* data, std::size_t len);

private:
    ProtocolHeader header_{};
    std::vector<std::uint8_t> payload_;
};

} // namespace rgs::network