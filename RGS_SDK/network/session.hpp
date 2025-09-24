#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <atomic>
#include <string>
#include <vector>

#include "network/message.hpp"
#include "network/dispatcher.hpp"
#include "security/nonce.hpp"
#include "security/hkdf.hpp"
#include "security/random.hpp"
#include "security/jwt.hpp"

namespace rgs::sdk::network {

class SessionManager; // forward

enum class SessionRole {
    ServerSide,
    ClientSide
};

class Session : public std::enable_shared_from_this<Session> {
public:
    using tcp = boost::asio::ip::tcp;

    // Server-side
    Session(boost::asio::io_context& io,
            tcp::socket socket,
            Dispatcher& dispatcher,
            std::weak_ptr<SessionManager> manager,
            std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator);

    // Client-side
    Session(boost::asio::io_context& io,
            Dispatcher& dispatcher,
            const std::string& server_host, uint16_t server_port,
            const std::string& jwt_token,
            const std::vector<uint8_t>& ikm);

    ~Session();

    void start();
    void close();

    bool send_plain(Message& msg);

    const std::string& login() const { return login_; }
    bool authenticated() const { return authenticated_; }

    bool validate_nonce(const uint8_t* iv);

    tcp::socket& socket() { return socket_; }

private:
    void do_read_header();
    void do_read_body(std::size_t body_len);
    void process_incoming();

    void server_handshake();
    void client_handshake(const std::string& host, uint16_t port);

    void write_encrypted(Message& msg);

private:
    boost::asio::io_context& io_;
    tcp::socket socket_;
    Dispatcher& dispatcher_;
    std::weak_ptr<SessionManager> manager_;
    SessionRole role_;
    std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator_;

    PacketHeader incoming_header_{};
    std::vector<uint8_t> incoming_ciphertext_;
    Message incoming_msg_;

    std::vector<uint8_t> aes_key_;
    rgs::sdk::security::NonceGenerator iv_gen_;
    std::atomic<uint64_t> last_iv_counter_{0};

    std::string jwt_token_;
    std::vector<uint8_t> client_ikm_;

    std::string login_;
    bool authenticated_{false};
};

} // namespace rgs::sdk::network
