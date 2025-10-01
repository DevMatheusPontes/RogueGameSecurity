#include "client_connector.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

ClientConnector::ClientConnector(boost::asio::io_context& io,
                                 const boost::asio::ip::tcp::endpoint& endpoint)
    : endpoint_(endpoint), socket_(io) {}

void ClientConnector::connect() {
    auto self = this;
    socket_.async_connect(endpoint_, [this, self](boost::system::error_code ec) {
        if (!ec) {
            auto session = std::make_shared<Session>(std::move(socket_));
            if (on_connected_) on_connected_(session);
            session->start();
        } else {
            rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Error, "Connect failed");
            if (on_error_) on_error_();
        }
    });
}

void ClientConnector::stop() {
    boost::system::error_code ec;
    socket_.close(ec);
}

} // namespace rgs::network