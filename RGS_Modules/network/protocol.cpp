#include "protocol.hpp"

namespace rgs::network {

void Protocol::encode_header(const ProtocolHeader& hdr, std::array<std::uint8_t, HEADER_SIZE>& out) {
    auto write16 = [&](std::size_t pos, std::uint16_t v) {
        out[pos] = static_cast<std::uint8_t>(v & 0xFF);
        out[pos+1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    };
    auto write32 = [&](std::size_t pos, std::uint32_t v) {
        out[pos] = static_cast<std::uint8_t>(v & 0xFF);
        out[pos+1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        out[pos+2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
        out[pos+3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    };

    write32(0, hdr.magic);
    write16(4, hdr.version);
    write16(6, hdr.header_size);
    write16(8, hdr.service);
    write16(10, hdr.flags);
    write32(12, hdr.payload_len);
    write32(16, hdr.crc32);
    write32(20, hdr.reserved);
}

std::optional<ProtocolHeader> Protocol::decode_header(const std::uint8_t* data, std::size_t len) {
    if (len < HEADER_SIZE) return std::nullopt;

    auto read16 = [&](std::size_t pos) {
        return static_cast<std::uint16_t>(data[pos] | (data[pos+1] << 8));
    };
    auto read32 = [&](std::size_t pos) {
        return static_cast<std::uint32_t>(data[pos] |
                                         (data[pos+1] << 8) |
                                         (data[pos+2] << 16) |
                                         (data[pos+3] << 24));
    };

    ProtocolHeader hdr;
    hdr.magic       = read32(0);
    hdr.version     = read16(4);
    hdr.header_size = read16(6);
    hdr.service     = read16(8);
    hdr.flags       = read16(10);
    hdr.payload_len = read32(12);
    hdr.crc32       = read32(16);
    hdr.reserved    = read32(20);

    if (hdr.magic != MAGIC || hdr.header_size != HEADER_SIZE) {
        return std::nullopt;
    }
    return hdr;
}

// Implementação simples de CRC32 (polinômio 0xEDB88320)
std::uint32_t Protocol::crc32(const std::uint8_t* data, std::size_t len) {
    static std::uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (std::uint32_t i = 0; i < 256; i++) {
            std::uint32_t c = i;
            for (std::size_t j = 0; j < 8; j++) {
                if (c & 1) c = 0xEDB88320U ^ (c >> 1);
                else c >>= 1;
            }
            table[i] = c;
        }
        init = true;
    }

    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t i = 0; i < len; i++) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

} // namespace rgs::network