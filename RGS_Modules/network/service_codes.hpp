#pragma once

#include <cstdint>

namespace rgs::network {

// Enum de códigos de serviço
enum ServiceCode : std::uint16_t {
    SERVICE_HELLO    = 1,
    SERVICE_PING     = 2,
    SERVICE_AUTH     = 3,
    SERVICE_REGISTER = 4,
    // Reservado para futuros serviços
};

} // namespace rgs::network