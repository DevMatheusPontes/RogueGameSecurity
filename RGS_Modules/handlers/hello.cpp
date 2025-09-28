#include "hello.hpp"
#include "../network/secure_channel.hpp"
#include "../network/packet_builder.hpp"
#include "../network/service_codes.hpp"

namespace rgs::handlers {

rgs::network::Handler Hello::create() {
    return [](rgs::network::Session& session, const rgs::network::Message& msg) {
        using namespace rgs::network;

        auto decoded = SecureChannel::decodeSecure(msg.encode());

        auto response = PacketBuilder::buildFromString(
            ServiceCode::Hello,
            0x0002,
            decoded.header().correlationId,
            "Hello ACK"
        );

        session.send(response.encode());
    };
}

}