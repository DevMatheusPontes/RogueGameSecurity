#include "message.hpp"

namespace rgs::modules::network {

Message::Message(ServiceCode svc, MessageType type) {
    hdr_.version = 1;
    hdr_.service = static_cast<uint8_t>(svc);
    hdr_.type    = static_cast<uint8_t>(type);
    hdr_.flags   = 0;
    hdr_.size    = 0;
}

uint8_t Message::version() const { return hdr_.version; }
ServiceCode Message::service() const { return static_cast<ServiceCode>(hdr_.service); }
MessageType Message::msgType() const { return static_cast<MessageType>(hdr_.type); }
uint8_t Message::flags() const { return hdr_.flags; }
void Message::setFlags(uint8_t f) { hdr_.flags = f; }

const std::vector<uint8_t>& Message::payload() const { return data_; }
void Message::setPayload(const std::vector<uint8_t>& p) { data_ = p; hdr_.size = static_cast<uint32_t>(data_.size()); }
void Message::setPayloadString(const std::string& s) { data_.assign(s.begin(), s.end()); hdr_.size = static_cast<uint32_t>(data_.size()); }
std::string Message::toString() const { return std::string(data_.begin(), data_.end()); }

std::vector<uint8_t> Message::toBuffer() const {
    return Protocol::serialize(hdr_, data_);
}

Message Message::fromBuffer(const std::vector<uint8_t>& buf) {
    auto [hdr, payload] = Protocol::deserialize(buf);
    Message m;
    m.hdr_ = hdr;
    m.data_ = std::move(payload);
    return m;
}

} // namespace rgs::modules::network