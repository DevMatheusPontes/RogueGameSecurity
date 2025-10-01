#include "session.hpp"

namespace rgs::network {

Session::Session(boost::asio::ip::tcp::socket socket)
    : socket_(std::move(socket)) {}

void Session::start() {
    do_read_header();
}

void Session::stop() {
    close();
}

void Session::async_send(const Message& msg) {
    auto data = msg.to_bytes();
    bool write_in_progress = !write_queue_.empty();
    write_queue_.push_back(std::move(data));
    if (!write_in_progress) {
        do_write();
    }
}

void Session::do_read_header() {
    auto self = shared_from_this();
    read_buffer_.resize(Protocol::HEADER_SIZE);
    boost::asio::async_read(socket_,
        boost::asio::buffer(read_buffer_),
        [this, self](boost::system::error_code ec, std::size_t /*len*/) {
            if (!ec) {
                auto hdr_opt = Protocol::decode_header(read_buffer_.data(), read_buffer_.size());
                if (!hdr_opt) {
                    rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Error, "Invalid header");
                    close();
                    return;
                }
                read_header_ = *hdr_opt;
                do_read_body(read_header_.payload_len);
            } else {
                close();
            }
        });
}

void Session::do_read_body(std::size_t body_len) {
    auto self = shared_from_this();
    read_buffer_.resize(body_len);
    boost::asio::async_read(socket_,
        boost::asio::buffer(read_buffer_),
        [this, self, body_len](boost::system::error_code ec, std::size_t /*len*/) {
            if (!ec) {
                auto msg_opt = Message::from_bytes(read_buffer_.data(),
                                                   Protocol::HEADER_SIZE + body_len);
                if (msg_opt && on_message_) {
                    on_message_(self, *msg_opt);
                }
                do_read_header();
            } else {
                close();
            }
        });
}

void Session::do_write() {
    auto self = shared_from_this();
    boost::asio::async_write(socket_,
        boost::asio::buffer(write_queue_.front()),
        [this, self](boost::system::error_code ec, std::size_t /*len*/) {
            if (!ec) {
                write_queue_.pop_front();
                if (!write_queue_.empty()) {
                    do_write();
                }
            } else {
                close();
            }
        });
}

void Session::close() {
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
    if (on_close_) {
        on_close_(shared_from_this());
    }
}

} // namespace rgs::network