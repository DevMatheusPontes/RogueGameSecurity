#include "register.hpp"
#include "../network/secure_channel.hpp"
#include "../network/packet_builder.hpp"
#include "../network/service_codes.hpp"

namespace rgs::handlers {

rgs::network::Handler Register::create() {
    return [](rgs::network::Session& session, const rgs::network::Message& msg) {
        using namespace rgs::network;

        auto decoded = SecureChannel::decodeSecure(msg.encode());

        // Aqui poderia validar dados de registro
        auto response = PacketBuilder::buildFromString(
            ServiceCode::Register,
            0x0002,
            decoded.header().correlationId,
            "Register OK"
        );

        session.send(response.encode());
    };
}

}