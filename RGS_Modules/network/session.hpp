#pragma once

#include <boost/asio.hpp>
#include <deque>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include "dispatcher.hpp"

namespace rgs::network {

class Session : public std::enable_shared_from_this<Session> {
public:
    using tcp = boost::asio::ip::tcp;

    Session(tcp::socket socket, Dispatcher& dispatcher);

    void start();
    void send(const std::vector<uint8_t>& data);
    void close();

    std::string id() const;
    std::string remoteIp() const;
    bool isOpen() const;

private:
    void doReadHeader();
    void doReadBody(std::size_t bodyLength);
    void doWrite();

    tcp::socket socket_;
    Dispatcher& dispatcher_;
    std::array<uint8_t, PROTOCOL_HEADER_SIZE> readHeader_;
    std::vector<uint8_t> readBody_;
    std::deque<std::vector<uint8_t>> writeQueue_;
    bool open_{true};
    std::string id_;
};

}