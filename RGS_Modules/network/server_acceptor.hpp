#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "session.hpp"

namespace rgs::network {

class ServerAcceptor {
public:
    ServerAcceptor(boost::asio::io_context& io, const boost::asio::ip::tcp::endpoint& endpoint);

    void start_accept();
    void stop();

    void set_on_new_session(std::function<void(SessionPtr)> cb) { on_new_session_ = std::move(cb); }

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    std::function<void(SessionPtr)> on_new_session_;
};

} // namespace rgs::network