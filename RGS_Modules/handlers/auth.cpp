#include "auth.hpp"
#include "utils/logger.hpp"
#include "security/secure_string.hpp"
#include "network/packet_builder.hpp"

namespace rgs::handlers {

void AuthHandler::handle(rgs::network::SessionPtr session, const rgs::network::Message& msg) {
    using namespace rgs::utils;
    using namespace rgs::security;

    SecureString logMsg("Received AUTH request");
    Logger::instance().log(LogLevel::Info, logMsg);

    // Aqui futuramente validaremos credenciais.
    SecureString reply("AUTH_OK");
    auto response = rgs::network::PacketBuilder::from_secure_string(msg.header().service, reply);
    session->async_send(response);
}

} // namespace rgs::handlers