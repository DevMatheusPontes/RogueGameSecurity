#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "session.hpp"
#include "dispatcher.hpp"

namespace rgs::network {

class ServerAcceptor {
public:
    using tcp = boost::asio::ip::tcp;

    ServerAcceptor(boost::asio::io_context& ctx, Dispatcher& dispatcher, uint16_t port);

    void start();
    void stop();

private:
    void doAccept();

    tcp::acceptor acceptor_;
    Dispatcher& dispatcher_;
    bool running_{false};
};

}