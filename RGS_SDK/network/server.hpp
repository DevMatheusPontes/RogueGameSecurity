#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "network/session.hpp"
#include "network/session_manager.hpp"
#include "network/dispatcher.hpp"

namespace rgs::sdk::network {

class Server {
public:
    using tcp = boost::asio::ip::tcp;

    Server(boost::asio::io_context& io, uint16_t port,
           Dispatcher& dispatcher,
           std::shared_ptr<SessionManager> manager,
           std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator);

    void start();
    void stop();

private:
    void do_accept();

private:
    boost::asio::io_context& io_;
    tcp::acceptor acceptor_;
    Dispatcher& dispatcher_;
    std::shared_ptr<SessionManager> manager_;
    std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator_;
    bool running_{false};
};

} // namespace rgs::sdk::network
