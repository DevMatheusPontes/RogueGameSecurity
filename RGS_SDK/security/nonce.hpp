#pragma once

#include <vector>
#include <cstdint>
#include <atomic>

namespace rgs::sdk::security {

// Gerador de IV único por sessão (12 bytes) para AES-GCM.
// Estrutura: 4 bytes de prefixo aleatório + 8 bytes contador monotônico.
class NonceGenerator {
public:
    NonceGenerator();

    // Próximo IV (12 bytes)
    std::vector<uint8_t> next_iv();

    // Reinicia contador (mantém prefixo)
    void reset();

private:
    uint32_t prefix_;           // aleatório por instância
    std::atomic<uint64_t> ctr_; // contador monotônico por sessão
};

} // namespace rgs::sdk::security
