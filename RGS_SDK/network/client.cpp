#include "network/client.hpp"

namespace rgs::sdk::network {

Client::Client(boost::asio::io_context& io,
               Dispatcher& dispatcher,
               const std::string& host, uint16_t port,
               const std::string& jwt_token,
               const std::vector<uint8_t>& ikm) {
    session_ = std::make_shared<Session>(io, dispatcher, host, port, jwt_token, ikm);
    session_->start();
}

} // namespace rgs::sdk::network
