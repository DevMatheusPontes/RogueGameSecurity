#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace rgs::sdk::security {

struct AesGcmResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag; // 16 bytes
};

class Crypto {
public:
    // key: 32 bytes (AES-256)
    // iv: 12 bytes (recomendado para GCM)
    // aad: dados adicionais autenticados (não criptografados), opcional
    static std::optional<AesGcmResult> aes256_gcm_encrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad = {}
    );

    // Retorna plaintext se sucesso; std::nullopt se tag inválida
    static std::optional<std::vector<uint8_t>> aes256_gcm_decrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad = {}
    );
};

} // namespace rgs::sdk::security
