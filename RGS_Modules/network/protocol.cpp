#include "protocol.hpp"
#include <cstring>

namespace rgs::modules::network {

void Protocol::writeLE32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFF);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

uint32_t Protocol::readLE32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) |
           (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) |
           (static_cast<uint32_t>(in[3]) << 24);
}

std::vector<uint8_t> Protocol::serialize(const ProtocolHeader& hdr, const std::vector<uint8_t>& payload) {
    if (payload.size() > PROTOCOL_MAX_PAYLOAD) {
        throw std::runtime_error("Payload excede limite de protocolo");
    }

    std::vector<uint8_t> buffer(PROTOCOL_HEADER_SIZE + payload.size());
    buffer[0] = hdr.version;
    buffer[1] = hdr.service;
    buffer[2] = hdr.type;
    buffer[3] = hdr.flags;
    writeLE32(buffer.data() + 4, static_cast<uint32_t>(payload.size()));

    if (!payload.empty()) {
        std::memcpy(buffer.data() + PROTOCOL_HEADER_SIZE, payload.data(), payload.size());
    }
    return buffer;
}

std::pair<ProtocolHeader, std::vector<uint8_t>> Protocol::deserialize(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < PROTOCOL_HEADER_SIZE) {
        throw std::runtime_error("Buffer menor que header");
    }

    ProtocolHeader hdr{};
    hdr.version = buffer[0];
    hdr.service = buffer[1];
    hdr.type    = buffer[2];
    hdr.flags   = buffer[3];
    hdr.size    = readLE32(buffer.data() + 4);

    if (hdr.size > PROTOCOL_MAX_PAYLOAD) {
        throw std::runtime_error("Header indica payload acima do limite");
    }

    const std::size_t expected = PROTOCOL_HEADER_SIZE + static_cast<std::size_t>(hdr.size);
    if (buffer.size() != expected) {
        throw std::runtime_error("Tamanho inconsistente entre header e buffer");
    }

    std::vector<uint8_t> payload;
    payload.resize(hdr.size);
    if (hdr.size > 0) {
        std::memcpy(payload.data(), buffer.data() + PROTOCOL_HEADER_SIZE, hdr.size);
    }

    return {hdr, std::move(payload)};
}

} // namespace rgs::modules::network