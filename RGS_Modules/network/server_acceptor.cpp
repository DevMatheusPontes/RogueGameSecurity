#include "server_acceptor.hpp"

namespace rgs::network {

ServerAcceptor::ServerAcceptor(boost::asio::io_context& ctx, Dispatcher& dispatcher, uint16_t port)
    : acceptor_(ctx, tcp::endpoint(tcp::v4(), port)), dispatcher_(dispatcher) {}

void ServerAcceptor::start() {
    running_ = true;
    doAccept();
}

void ServerAcceptor::stop() {
    running_ = false;
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void ServerAcceptor::doAccept() {
    if (!running_) return;

    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<Session>(std::move(socket), dispatcher_);
            session->start();
        }
        doAccept();
    });
}

}