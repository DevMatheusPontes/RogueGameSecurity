#include "message.hpp"

namespace rgs::network {

Message::Message(std::uint16_t service, std::uint16_t flags, std::vector<std::uint8_t> payload)
    : payload_(std::move(payload)) {
    header_.magic       = Protocol::MAGIC;
    header_.version     = Protocol::VERSION;
    header_.header_size = static_cast<std::uint16_t>(Protocol::HEADER_SIZE);
    header_.service     = service;
    header_.flags       = flags;
    header_.payload_len = static_cast<std::uint32_t>(payload_.size());
    header_.crc32       = Protocol::crc32(payload_.data(), payload_.size());
    header_.reserved    = 0;
}

std::vector<std::uint8_t> Message::to_bytes() const {
    std::vector<std::uint8_t> out(Protocol::HEADER_SIZE + payload_.size());
    std::array<std::uint8_t, Protocol::HEADER_SIZE> hdr_bytes{};
    Protocol::encode_header(header_, hdr_bytes);
    std::copy(hdr_bytes.begin(), hdr_bytes.end(), out.begin());
    std::copy(payload_.begin(), payload_.end(), out.begin() + Protocol::HEADER_SIZE);
    return out;
}

std::optional<Message> Message::from_bytes(const std::uint8_t* data, std::size_t len) {
    auto hdr_opt = Protocol::decode_header(data, len);
    if (!hdr_opt) return std::nullopt;
    auto hdr = *hdr_opt;

    if (len < Protocol::HEADER_SIZE + hdr.payload_len) return std::nullopt;

    std::vector<std::uint8_t> payload(hdr.payload_len);
    std::copy(data + Protocol::HEADER_SIZE, data + Protocol::HEADER_SIZE + hdr.payload_len, payload.begin());

    // Verifica CRC
    auto crc = Protocol::crc32(payload.data(), payload.size());
    if (crc != hdr.crc32) return std::nullopt;

    Message msg;
    msg.header_ = hdr;
    msg.payload_ = std::move(payload);
    return msg;
}

} // namespace rgs::network