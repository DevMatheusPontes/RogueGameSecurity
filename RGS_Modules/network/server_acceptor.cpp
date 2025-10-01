#include "server_acceptor.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

ServerAcceptor::ServerAcceptor(boost::asio::io_context& io,
                               const boost::asio::ip::tcp::endpoint& endpoint)
    : acceptor_(io, endpoint) {}

void ServerAcceptor::start_accept() {
    do_accept();
}

void ServerAcceptor::stop() {
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void ServerAcceptor::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<Session>(std::move(socket));
            if (on_new_session_) {
                on_new_session_(session);
            }
            session->start();
        } else {
            rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Error, "Accept failed");
        }
        do_accept();
    });
}

} // namespace rgs::network