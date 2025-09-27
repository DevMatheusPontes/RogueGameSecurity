#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <array>
#include <vector>
#include "message.hpp"
#include "dispatcher.hpp"

namespace rgs::modules::network {

class Session : public std::enable_shared_from_this<Session> {
public:
    using tcp = boost::asio::ip::tcp;

    explicit Session(boost::asio::io_context& io, Dispatcher* dispatcher);

    tcp::socket& socket();
    void start();
    void send(const Message& msg);
    void close();

private:
    void doReadHeader();
    void doReadBody(std::size_t bodySize);

    tcp::socket socket_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    Dispatcher* dispatcher_{nullptr};

    std::array<uint8_t, PROTOCOL_HEADER_SIZE> headerRaw_{};
    std::vector<uint8_t> readBuffer_;
};

} // namespace rgs::modules::network