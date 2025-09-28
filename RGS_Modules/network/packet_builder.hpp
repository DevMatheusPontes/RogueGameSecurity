#pragma once

#include "message.hpp"
#include "service_codes.hpp"
#include <vector>
#include <cstdint>
#include <string>

namespace rgs::network {

class PacketBuilder {
public:
    static Message build(ServiceCode code, uint16_t messageType,
                         uint32_t correlationId,
                         const std::vector<uint8_t>& payload);

    static Message buildFromString(ServiceCode code, uint16_t messageType,
                                   uint32_t correlationId,
                                   const std::string& text);
};

}