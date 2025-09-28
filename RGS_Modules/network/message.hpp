#include "protocol.hpp"

namespace rgs::network {

ProtocolHeader ProtocolHeader::parse(const std::array<uint8_t, PROTOCOL_HEADER_SIZE>& raw) {
    ProtocolHeader h;
    h.version        = raw[0];
    h.flags          = raw[1];
    h.serviceCode    = (raw[2] << 8) | raw[3];
    h.messageType    = (raw[4] << 8) | raw[5];
    h.correlationId  = (raw[6] << 24) | (raw[7] << 16) | (raw[8] << 8) | raw[9];
    h.payloadLength  = (raw[10] << 24) | (raw[11] << 16) | (raw[12] << 8) | raw[13];
    h.reserved       = (raw[14] << 24) | (raw[15] << 16) | (raw[16] << 8) | raw[17];
    return h;
}

std::array<uint8_t, PROTOCOL_HEADER_SIZE> ProtocolHeader::build(const ProtocolHeader& h) {
    std::array<uint8_t, PROTOCOL_HEADER_SIZE> raw{};
    raw[0]  = h.version;
    raw[1]  = h.flags;
    raw[2]  = h.serviceCode >> 8;
    raw[3]  = h.serviceCode & 0xFF;
    raw[4]  = h.messageType >> 8;
    raw[5]  = h.messageType & 0xFF;
    raw[6]  = h.correlationId >> 24;
    raw[7]  = (h.correlationId >> 16) & 0xFF;
    raw[8]  = (h.correlationId >> 8) & 0xFF;
    raw[9]  = h.correlationId & 0xFF;
    raw[10] = h.payloadLength >> 24;
    raw[11] = (h.payloadLength >> 16) & 0xFF;
    raw[12] = (h.payloadLength >> 8) & 0xFF;
    raw[13] = h.payloadLength & 0xFF;
    raw[14] = h.reserved >> 24;
    raw[15] = (h.reserved >> 16) & 0xFF;
    raw[16] = (h.reserved >> 8) & 0xFF;
    raw[17] = h.reserved & 0xFF;
    return raw;
}

bool validateHeader(const ProtocolHeader& h) {
    return h.version == 1 && h.payloadLength <= 65536;
}

}