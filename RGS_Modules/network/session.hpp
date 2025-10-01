#pragma once

#include <boost/asio.hpp>
#include <deque>
#include <memory>
#include <vector>
#include <cstdint>
#include <functional>
#include "protocol.hpp"
#include "message.hpp"
#include "threading/timer_service.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

// Forward declaration
class Session;
using SessionPtr = std::shared_ptr<Session>;

// Callback para eventos de sessão
using SessionCallback = std::function<void(SessionPtr)>;

// Gerencia uma conexão (TCP) com leitura/escrita assíncrona
class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(boost::asio::ip::tcp::socket socket);

    void start();
    void stop();

    void async_send(const Message& msg);

    void set_on_close(SessionCallback cb) { on_close_ = std::move(cb); }
    void set_on_message(std::function<void(SessionPtr, Message)> cb) { on_message_ = std::move(cb); }

    boost::asio::ip::tcp::socket& socket() { return socket_; }

private:
    void do_read_header();
    void do_read_body(std::size_t body_len);
    void do_write();

    void close();

    boost::asio::ip::tcp::socket socket_;
    ProtocolHeader read_header_{};
    std::vector<std::uint8_t> read_buffer_;
    std::deque<std::vector<std::uint8_t>> write_queue_;

    SessionCallback on_close_;
    std::function<void(SessionPtr, Message)> on_message_;
};

} // namespace rgs::network