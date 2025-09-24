#pragma once
#include <cstdint>

namespace rgs::sdk::network {

// Serviços do protocolo
enum class ServiceCode : uint32_t {
    Heartbeat = 1,
    Auth      = 2,
    Chat      = 3,
    Broadcast = 4,
    Custom    = 100
};

} // namespace rgs::sdk::network
