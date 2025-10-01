#pragma once

namespace rgs::network {

// SecureChannel: stub para futura integração TLS.
// Mantém interface mínima para compilar e evoluir.
class SecureChannel {
public:
    void initialize();
    void shutdown();
};

} // namespace rgs::network