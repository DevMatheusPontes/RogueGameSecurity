#include <iostream>
#include <boost/asio.hpp>

#include "utils/logger.hpp"
#include "utils/console_color.hpp"
#include "network/server_acceptor.hpp"
#include "network/router.hpp"
#include "network/service_codes.hpp"
#include "handlers/hello.hpp"
#include "handlers/ping.hpp"
#include "handlers/auth.hpp"
#include "handlers/register.hpp"
#include "network/connection_manager.hpp"

using namespace rgs::utils;
using namespace rgs::network;
using namespace rgs::handlers;

int main() {
    try {
        boost::asio::io_context io;

        // Endpoint: localhost:9000
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), 9000);

        ServerAcceptor acceptor(io, endpoint);
        ConnectionManager conn_mgr;
        Router router;

        // Registrar rotas
        router.register_route(SERVICE_HELLO,  [](SessionPtr s, const Message& m){ HelloHandler::handle(s, m); });
        router.register_route(SERVICE_PING,   [](SessionPtr s, const Message& m){ PingHandler::handle(s, m); });
        router.register_route(SERVICE_AUTH,   [](SessionPtr s, const Message& m){ AuthHandler::handle(s, m); });
        router.register_route(SERVICE_REGISTER,[](SessionPtr s, const Message& m){ RegisterHandler::handle(s, m); });

        // Callback de nova sessão
        acceptor.set_on_new_session([&](SessionPtr session) {
            Logger::instance().log(LogLevel::Info, "New connection accepted");
            conn_mgr.add(session);

            session->set_on_message([&](SessionPtr s, Message msg) {
                router.route(s, msg);
            });
        });

        Logger::instance().log(LogLevel::Info, "Central starting on port 9000");

        acceptor.start_accept();
        io.run();

    } catch (const std::exception& ex) {
        Logger::instance().log(LogLevel::Error, ex.what());
    }

    return 0;
}