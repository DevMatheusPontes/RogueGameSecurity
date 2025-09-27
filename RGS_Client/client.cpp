#include "client.hpp"
#include "network/io_context_pool.hpp"
#include "network/session.hpp"
#include "network/protocol.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>

using namespace rgs::modules::network;
using tcp = boost::asio::ip::tcp;

namespace {
    std::unique_ptr<IoContextPool> pool;
    std::shared_ptr<Session> session;
    std::string g_host;
    int g_port = 0;
}

namespace rgs::client {

void start(const std::string& host, int port) {
    try {
        g_host = host;
        g_port = port;

        pool = std::make_unique<IoContextPool>(2);
        auto& io = pool->next();

        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(g_host, std::to_string(g_port));

        session = std::make_shared<Session>(io);
        boost::asio::async_connect(
            session->socket(), endpoints,
            [](boost::system::error_code ec, const tcp::endpoint&) {
                if (!ec) {
                    std::cout << "[Client] Connected to Central\n";
                    session->start();

                    // Envia mensagem usando o protocolo
                    ProtocolMessage msg = ProtocolMessage::fromString(MessageType::Hello, "Hello from RGS_Client!");
                    session->send(msg);
                } else {
                    std::cerr << "[Client] connect error: " << ec.message() << std::endl;
                }
            }
        );

        pool->run();

        std::cout << "[Client] Pressione ENTER para encerrar...\n";
        std::cin.get();

        stop();

    } catch (const std::exception& e) {
        std::cerr << "[Client] fatal: " << e.what() << std::endl;
    }
}

void stop() {
    try {
        if (session) session->close();
        if (pool) pool->stop();
        session.reset();
        pool.reset();
    } catch (...) {}
}

} // namespace rgs::client