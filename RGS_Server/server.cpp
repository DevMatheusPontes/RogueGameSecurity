#include "server.hpp"

#include "utils/logger.hpp"
#include "network/client_connector.hpp"
#include "network/reconnect_strategy.hpp"
#include "network/packet_builder.hpp"
#include "network/service_codes.hpp"
#include "security/secure_string.hpp"

#include <boost/asio.hpp>
#include <thread>
#include <atomic>
#include <memory>

namespace {
    std::unique_ptr<boost::asio::io_context> io;
    std::unique_ptr<std::thread> io_thread;
    std::atomic<bool> running{false};
    std::shared_ptr<rgs::network::ClientConnector> connector;
    std::unique_ptr<rgs::network::ReconnectStrategy> reconnect;
}

namespace rgs::server {

void StartServer() {
    if (running.exchange(true)) return;

    io = std::make_unique<boost::asio::io_context>();
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::address::from_string("127.0.0.1"), 9000);

    reconnect = std::make_unique<rgs::network::ReconnectStrategy>(
        std::chrono::milliseconds(1000), std::chrono::milliseconds(10000));

    connector = std::make_shared<rgs::network::ClientConnector>(*io, endpoint);

    std::function<void()> do_connect;

    do_connect = [&]() {
        connector->set_on_connected([&](rgs::network::SessionPtr session) {
            rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Info,
                                               "Server connected to Central", false);

            reconnect->reset();

            // Enviar REGISTER
            rgs::security::SecureString reg("REGISTER_SERVER");
            auto msg = rgs::network::PacketBuilder::from_secure_string(SERVICE_REGISTER, reg);
            session->async_send(msg);

            session->set_on_message([&](rgs::network::SessionPtr s, rgs::network::Message m) {
                switch (m.header().service) {
                    case SERVICE_PING: {
                        rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Debug,
                                                           "Server received PING", false);
                        rgs::security::SecureString pong("PONG_FROM_SERVER");
                        auto reply = rgs::network::PacketBuilder::from_secure_string(SERVICE_PING, pong);
                        s->async_send(reply);
                        break;
                    }
                    case SERVICE_REGISTER:
                        rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Info,
                                                           "REGISTER response received", false);
                        break;
                    default:
                        rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Warning,
                                                           "Server unknown service code", false);
                        break;
                }
            });

            session->set_on_close([&](rgs::network::SessionPtr) {
                rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Warning,
                                                   "Server disconnected", false);
                auto delay = reconnect->next_delay();
                std::this_thread::sleep_for(delay);
                do_connect();
            });
        });

                connector->set_on_error([&]() {
            rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Error,
                                               "Server connection failed", false);
            auto delay = reconnect->next_delay();
            std::this_thread::sleep_for(delay);
            do_connect();
        });

        connector->connect();
    };

    do_connect();

    io_thread = std::make_unique<std::thread>([]() { io->run(); });
}

void StopServer() {
    if (!running.exchange(false)) return;
    io->stop();
    if (io_thread && io_thread->joinable()) io_thread->join();
    io.reset();
    io_thread.reset();
    connector.reset();
    reconnect.reset();
}

} // namespace rgs::server