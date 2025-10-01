#pragma once

#include <boost/asio.hpp>
#include <functional>
#include "session.hpp"

namespace rgs::network {

class ClientConnector {
public:
    ClientConnector(boost::asio::io_context& io,
                    const boost::asio::ip::tcp::endpoint& endpoint);

    void connect();
    void stop();

    void set_on_connected(std::function<void(SessionPtr)> cb) { on_connected_ = std::move(cb); }
    void set_on_error(std::function<void()> cb) { on_error_ = std::move(cb); }

private:
    boost::asio::ip::tcp::endpoint endpoint_;
    boost::asio::ip::tcp::socket socket_;
    std::function<void(SessionPtr)> on_connected_;
    std::function<void()> on_error_;
};

} // namespace rgs::network