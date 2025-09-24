#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "network/session.hpp"
#include "network/dispatcher.hpp"

namespace rgs::sdk::network {

class Client {
public:
    Client(boost::asio::io_context& io,
           Dispatcher& dispatcher,
           const std::string& host, uint16_t port,
           const std::string& jwt_token,
           const std::vector<uint8_t>& ikm);

    std::shared_ptr<Session> session() const { return session_; }

private:
    std::shared_ptr<Session> session_;
};

} // namespace rgs::sdk::network
