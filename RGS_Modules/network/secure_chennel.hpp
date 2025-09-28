#pragma once

#include "session.hpp"
#include "message.hpp"
#include "packet_builder.hpp"
#include "service_codes.hpp"
#include "../security/obfuscate.hpp"

namespace rgs::network {

class SecureChannel {
public:
    explicit SecureChannel(Session& session);

    void sendSecure(ServiceCode code, uint16_t messageType,
                    uint32_t correlationId, const std::vector<uint8_t>& payload);

    void sendSecureString(ServiceCode code, uint16_t messageType,
                          uint32_t correlationId, const std::string& text);

    // Decodifica e de-ofusca payload recebido
    static Message decodeSecure(const std::vector<uint8_t>& raw);

private:
    Session& session_;
};

}