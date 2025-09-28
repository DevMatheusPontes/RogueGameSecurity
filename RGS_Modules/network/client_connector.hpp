#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include "session.hpp"
#include "dispatcher.hpp"

namespace rgs::network {

class ClientConnector : public std::enable_shared_from_this<ClientConnector> {
public:
    using tcp = boost::asio::ip::tcp;

    ClientConnector(boost::asio::io_context& ctx, Dispatcher& dispatcher);

    void connect(const std::string& host, uint16_t port, std::function<void(std::shared_ptr<Session>)> onConnect);
    void stop();

private:
    boost::asio::io_context& context_;
    tcp::resolver resolver_;
    Dispatcher& dispatcher_;
    bool running_{false};
};

}