#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace rgs::sdk::security {

struct SessionKeys {
    std::vector<uint8_t> enc_key; // 32 bytes AES-256
    std::vector<uint8_t> mac_key; // 32 bytes HMAC-SHA256
};

class HKDF {
public:
    // HKDF-SHA256 genérico
    static std::optional<std::vector<uint8_t>> derive(
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& ikm,
        const std::vector<uint8_t>& info,
        std::size_t length);

    // Deriva chaves de sessão a partir de segredo base (ikm) + salt.
    // info separa o contexto para evitar colisões em diferentes usos.
    static std::optional<SessionKeys> derive_session_keys(
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& ikm,
        const std::string& info_context = "RGS/SESSION");
};

} // namespace rgs::sdk::security
