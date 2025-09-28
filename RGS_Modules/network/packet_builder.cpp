#include "packet_builder.hpp"

namespace rgs::network {

Message PacketBuilder::build(ServiceCode code, uint16_t messageType,
                             uint32_t correlationId,
                             const std::vector<uint8_t>& payload) {
    ProtocolHeader h;
    h.version       = 1;
    h.flags         = 0;
    h.serviceCode   = static_cast<uint16_t>(code);
    h.messageType   = messageType;
    h.correlationId = correlationId;
    h.payloadLength = static_cast<uint32_t>(payload.size());
    h.reserved      = 0;

    return Message(h, payload);
}

Message PacketBuilder::buildFromString(ServiceCode code, uint16_t messageType,
                                       uint32_t correlationId,
                                       const std::string& text) {
    std::vector<uint8_t> payload(text.begin(), text.end());
    return build(code, messageType, correlationId, payload);
}

}