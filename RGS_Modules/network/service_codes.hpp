#pragma once

#include <cstdint>

namespace rgs::network {

enum class ServiceCode : uint16_t {
    Hello           = 0x0001,
    Register        = 0x0100,
    Auth            = 0x0101,
    Ping            = 0x0200,
    PlayerCommand   = 0x0300,
    ServerStatus    = 0x0400,
    InternalError   = 0xFFFF
};

}