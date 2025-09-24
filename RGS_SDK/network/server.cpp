#include "network/server.hpp"

namespace rgs::sdk::network {

Server::Server(boost::asio::io_context& io, uint16_t port,
               Dispatcher& dispatcher,
               std::shared_ptr<SessionManager> manager,
               std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator)
    : io_(io),
      acceptor_(io, tcp::endpoint(tcp::v4(), port)),
      dispatcher_(dispatcher),
      manager_(std::move(manager)),
      jwt_validator_(std::move(jwt_validator)) {}

void Server::start() {
    running_ = true;
    do_accept();
}

void Server::stop() {
    running_ = false;
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void Server::do_accept() {
    if (!running_) return;
    acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<Session>(
                io_, std::move(socket), dispatcher_, manager_, jwt_validator_);
            session->start();
        }
        do_accept();
    });
}

} // namespace rgs::sdk::network
