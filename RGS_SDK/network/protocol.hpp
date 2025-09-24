#pragma once

#include <cstdint>

namespace rgs::sdk::network {

// 4 bytes assinatura para validar pacotes
constexpr uint32_t MAGIC_VALUE = 'RGSS'; 

// Tipos do protocolo (deve alinhar com ServiceCode)
enum class MessageType : uint32_t {
    HandshakeRequest = 1,
    HandshakeAccept  = 2,
    Data             = 3,
    Ping             = 4,
    Shutdown         = 5
};

struct PacketHeader {
    uint32_t magic;       // MAGIC_VALUE
    uint32_t type;        // ServiceCode/MessageType
    uint32_t length;      // tamanho do ciphertext
    uint8_t  iv[12];      // IV/nonce único por pacote (AES-GCM)
    uint8_t  tag[16];     // tag de autenticação GCM
};

} // namespace rgs::sdk::network
