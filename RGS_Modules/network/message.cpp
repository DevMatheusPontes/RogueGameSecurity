#include "message.hpp"

namespace rgs::network {

Message::Message() : header_{}, payload_{} {}

Message::Message(const ProtocolHeader& h, std::vector<uint8_t> p)
    : header_(h), payload_(std::move(p)) {}

const ProtocolHeader& Message::header() const {
    return header_;
}

const std::vector<uint8_t>& Message::payload() const {
    return payload_;
}

std::vector<uint8_t> Message::encode() const {
    auto rawHeader = ProtocolHeader::build(header_);
    std::vector<uint8_t> result;
    result.reserve(PROTOCOL_HEADER_SIZE + payload_.size());
    result.insert(result.end(), rawHeader.begin(), rawHeader.end());
    result.insert(result.end(), payload_.begin(), payload_.end());
    return result;
}

Message Message::decode(const std::vector<uint8_t>& raw) {
    if (raw.size() < PROTOCOL_HEADER_SIZE) throw std::runtime_error("Pacote inválido");

    std::array<uint8_t, PROTOCOL_HEADER_SIZE> rawHeader{};
    std::copy_n(raw.begin(), PROTOCOL_HEADER_SIZE, rawHeader.begin());

    auto h = ProtocolHeader::parse(rawHeader);
    std::vector<uint8_t> payload(raw.begin() + PROTOCOL_HEADER_SIZE, raw.end());

    return Message(h, std::move(payload));
}

}