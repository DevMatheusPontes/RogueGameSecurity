#pragma once
#include "protocol.hpp"
#include <vector>
#include <string>

namespace rgs::modules::network {

class Message {
public:
    Message() = default;
    Message(ServiceCode svc, MessageType type);

    // Header accessors
    uint8_t version() const;
    ServiceCode service() const;
    MessageType msgType() const;
    uint8_t flags() const;
    void setFlags(uint8_t f);

    // Payload
    const std::vector<uint8_t>& payload() const;
    void setPayload(const std::vector<uint8_t>& p);
    void setPayloadString(const std::string& s);
    std::string toString() const;

    // Wire format
    std::vector<uint8_t> toBuffer() const;
    static Message fromBuffer(const std::vector<uint8_t>& buf);

private:
    ProtocolHeader hdr_{};
    std::vector<uint8_t> data_;
};

} // namespace rgs::modules::network