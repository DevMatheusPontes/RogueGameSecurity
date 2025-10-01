#pragma once

#include <vector>
#include <cstdint>
#include <string_view>
#include "message.hpp"
#include "security/secure_string.hpp"

namespace rgs::network {

// Utilitário para construir mensagens a partir de strings ou binários.
// Observação: para reduzir exposição de texto sensível em memória,
// quando possível use from_secure_string (decrypt → use → wipe).
class PacketBuilder {
public:
    // Constrói uma mensagem a partir de um texto (UTF-8).
    static Message from_string(std::uint16_t service, std::string_view text,
                               std::uint16_t flags = 0);

    // Constrói uma mensagem a partir de SecureString (decrypt → use → wipe).
    static Message from_secure_string(std::uint16_t service,
                                      rgs::security::SecureString& s,
                                      std::uint16_t flags = 0);

    // Constrói uma mensagem a partir de bytes (cópia do buffer).
    static Message from_bytes(std::uint16_t service,
                              const std::vector<std::uint8_t>& data,
                              std::uint16_t flags = 0);

    // Constrói uma mensagem a partir de ponteiro/len (cópia do buffer).
    static Message from_bytes(std::uint16_t service,
                              const std::uint8_t* data, std::size_t len,
                              std::uint16_t flags = 0);
};

} // namespace rgs::network