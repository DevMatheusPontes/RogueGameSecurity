#include "secure_channel.hpp"

namespace rgs::network {

SecureChannel::SecureChannel(Session& session) : session_(session) {}

void SecureChannel::sendSecure(ServiceCode code, uint16_t messageType,
                               uint32_t correlationId, const std::vector<uint8_t>& payload) {
    auto encrypted = rgs::security::Obfuscate::apply(payload);
    auto msg = PacketBuilder::build(code, messageType, correlationId, encrypted);
    session_.send(msg.encode());
}

void SecureChannel::sendSecureString(ServiceCode code, uint16_t messageType,
                                     uint32_t correlationId, const std::string& text) {
    std::vector<uint8_t> payload(text.begin(), text.end());
    sendSecure(code, messageType, correlationId, payload);
}

Message SecureChannel::decodeSecure(const std::vector<uint8_t>& raw) {
    auto msg = Message::decode(raw);
    auto decrypted = rgs::security::Obfuscate::revert(msg.payload());
    return Message(msg.header(), decrypted);
}

}