#include "auth.hpp"
#include "../network/secure_channel.hpp"
#include "../network/packet_builder.hpp"
#include "../network/service_codes.hpp"

namespace rgs::handlers {

rgs::network::Handler Auth::create() {
    return [](rgs::network::Session& session, const rgs::network::Message& msg) {
        using namespace rgs::network;

        auto decoded = SecureChannel::decodeSecure(msg.encode());

        // Aqui poderia validar credenciais
        auto response = PacketBuilder::buildFromString(
            ServiceCode::Auth,
            0x0002,
            decoded.header().correlationId,
            "Auth OK"
        );

        session.send(response.encode());
    };
}

}