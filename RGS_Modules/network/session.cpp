#include "session.hpp"
#include "protocol.hpp"
#include <iostream>
#include <sstream>

namespace rgs::network {

Session::Session(tcp::socket socket, Dispatcher& dispatcher)
    : socket_(std::move(socket)), dispatcher_(dispatcher) {
    std::ostringstream oss;
    oss << this; // id simples baseado no ponteiro
    id_ = oss.str();
}

void Session::start() {
    doReadHeader();
}

void Session::send(const std::vector<uint8_t>& data) {
    auto self(shared_from_this());
    boost::asio::post(socket_.get_executor(), [this, self, data]() {
        bool writing = !writeQueue_.empty();
        writeQueue_.push_back(data);
        if (!writing) doWrite();
    });
}

void Session::close() {
    if (!open_) return;
    open_ = false;
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

std::string Session::id() const {
    return id_;
}

std::string Session::remoteIp() const {
    try {
        return socket_.remote_endpoint().address().to_string();
    } catch (...) {
        return "unknown";
    }
}

bool Session::isOpen() const {
    return open_;
}

void Session::doReadHeader() {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, boost::asio::buffer(readHeader_),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                auto header = ProtocolHeader::parse(readHeader_);
                readBody_.resize(header.payloadLength);
                doReadBody(header.payloadLength);
            } else {
                close();
            }
        });
}

void Session::doReadBody(std::size_t bodyLength) {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, boost::asio::buffer(readBody_),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                std::vector<uint8_t> raw;
                raw.insert(raw.end(), readHeader_.begin(), readHeader_.end());
                raw.insert(raw.end(), readBody_.begin(), readBody_.end());
                dispatcher_.dispatch(*this, raw);
                doReadHeader();
            } else {
                close();
            }
        });
}

void Session::doWrite() {
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(writeQueue_.front()),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                writeQueue_.pop_front();
                if (!writeQueue_.empty()) doWrite();
            } else {
                close();
            }
        });
}

}