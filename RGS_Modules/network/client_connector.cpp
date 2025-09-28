#include "client_connector.hpp"

namespace rgs::network {

ClientConnector::ClientConnector(boost::asio::io_context& ctx, Dispatcher& dispatcher)
    : context_(ctx), resolver_(ctx), dispatcher_(dispatcher) {}

void ClientConnector::connect(const std::string& host, uint16_t port,
                              std::function<void(std::shared_ptr<Session>)> onConnect) {
    running_ = true;
    auto self = shared_from_this();

    resolver_.async_resolve(host, std::to_string(port),
        [this, self, onConnect](const boost::system::error_code& ec, tcp::resolver::results_type results) {
            if (!ec) {
                auto socket = std::make_shared<tcp::socket>(context_);
                boost::asio::async_connect(*socket, results,
                    [this, self, socket, onConnect](const boost::system::error_code& ec, const tcp::endpoint&) {
                        if (!ec) {
                            auto session = std::make_shared<Session>(std::move(*socket), dispatcher_);
                            session->start();
                            if (onConnect) onConnect(session);
                        }
                    });
            }
        });
}

void ClientConnector::stop() {
    running_ = false;
    boost::system::error_code ec;
    resolver_.cancel();
}

}