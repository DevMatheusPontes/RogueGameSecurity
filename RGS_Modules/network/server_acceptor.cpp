#include "server_acceptor.hpp"
#include <iostream>

namespace rgs::modules::network {

ServerAcceptor::ServerAcceptor(boost::asio::io_context& io, unsigned short port)
    : io_(io),
      acceptor_(io, tcp::endpoint(tcp::v4(), port)) {}

void ServerAcceptor::onClientConnected(std::function<void(std::shared_ptr<Session>)> cb) {
    clientConnectedCb_ = std::move(cb);
}

void ServerAcceptor::start() {
    if (running_) return;
    running_ = true;
    std::cout << "[Central] Listening on port " << acceptor_.local_endpoint().port() << std::endl;
    doAccept();
}

void ServerAcceptor::stop() {
    running_ = false;
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void ServerAcceptor::doAccept() {
    auto session = std::make_shared<Session>(io_);
    acceptor_.async_accept(
        session->socket(),
        [this, session](boost::system::error_code ec) {
            if (!running_) return;
            if (!ec) {
                std::cout << "[Central] Client connected" << std::endl;
                session->start();
                if (clientConnectedCb_) clientConnectedCb_(session);
            } else {
                std::cerr << "[Central] accept error: " << ec.message() << std::endl;
            }
            doAccept();
        }
    );
}

} // namespace rgs::modules::network