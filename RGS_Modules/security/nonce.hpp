#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>

namespace rgs::utils {

// Gera nonces criptograficamente fortes (quando disponível).
// Retorna bytes e utilitário para hex. Sempre limpa buffers temporários quando aplicável.
class Nonce {
public:
    // Gera 'len' bytes de nonce.
    static std::vector<std::uint8_t> bytes(std::size_t len);

    // Converte bytes para string hex em minúsculas.
    static std::string to_hex(std::string_view bytes);

    // Converte vetor de bytes para string hex em minúsculas.
    static std::string to_hex(const std::vector<std::uint8_t>& bytes);

private:
    static void wipe(std::vector<std::uint8_t>& v) noexcept;
};

} // namespace rgs::utils