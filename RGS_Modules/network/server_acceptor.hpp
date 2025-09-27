#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include "session.hpp"

namespace rgs::modules::network {

class ServerAcceptor {
public:
    using tcp = boost::asio::ip::tcp;

    ServerAcceptor(boost::asio::io_context& io, unsigned short port);

    void start();
    void stop();

    void onClientConnected(std::function<void(std::shared_ptr<Session>)> cb);

private:
    void doAccept();

    boost::asio::io_context& io_;
    tcp::acceptor acceptor_;
    std::function<void(std::shared_ptr<Session>)> clientConnectedCb_;
    bool running_{false};
};

} // namespace rgs::modules::network