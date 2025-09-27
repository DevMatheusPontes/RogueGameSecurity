#include "session.hpp"
#include <iostream>
#include <cstring>

namespace rgs::modules::network {

static constexpr std::size_t MAX_PAYLOAD_SIZE = PROTOCOL_MAX_PAYLOAD;

Session::Session(boost::asio::io_context& io, Dispatcher* dispatcher)
    : socket_(io),
      strand_(boost::asio::make_strand(io)),
      dispatcher_(dispatcher) {}

Session::tcp::socket& Session::socket() { return socket_; }

void Session::start() { doReadHeader(); }

void Session::send(const Message& msg) {
    auto self = shared_from_this();
    auto buffer = msg.toBuffer();

    boost::asio::async_write(
        socket_,
        boost::asio::buffer(buffer),
        boost::asio::bind_executor(
            strand_,
            [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    std::cerr << "[Session] write error: " << ec.message() << std::endl;
                    close();
                }
            }
        )
    );
}

void Session::doReadHeader() {
    auto self = shared_from_this();
    boost::asio::async_read(
        socket_,
        boost::asio::buffer(headerRaw_.data(), headerRaw_.size()),
        boost::asio::bind_executor(
            strand_,
            [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    if (ec != boost::asio::error::eof)
                        std::cerr << "[Session] header read error: " << ec.message() << std::endl;
                    close();
                    return;
                }

                const uint32_t sizeLE = Protocol::readLE32(headerRaw_.data() + 4);
                if (sizeLE > MAX_PAYLOAD_SIZE) {
                    std::cerr << "[Session] payload muito grande (" << sizeLE << "), desconectando\n";
                    close();
                    return;
                }

                doReadBody(static_cast<std::size_t>(sizeLE));
            }
        )
    );
}

void Session::doReadBody(std::size_t bodySize) {
    auto self = shared_from_this();
    readBuffer_.resize(bodySize);

    boost::asio::async_read(
        socket_,
        boost::asio::buffer(readBuffer_.data(), bodySize),
        boost::asio::bind_executor(
            strand_,
            [this, self, bodySize](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    std::cerr << "[Session] body read error: " << ec.message() << std::endl;
                    close();
                    return;
                }

                try {
                    std::vector<uint8_t> full(PROTOCOL_HEADER_SIZE + bodySize);
                    std::memcpy(full.data(), headerRaw_.data(), PROTOCOL_HEADER_SIZE);
                    if (bodySize > 0) {
                        std::memcpy(full.data() + PROTOCOL_HEADER_SIZE, readBuffer_.data(), bodySize);
                    }

                    // Coerência header/corpo
                    const uint32_t headerSize = Protocol::readLE32(full.data() + 4);
                    if (headerSize != bodySize) {
                        throw std::runtime_error("Header size difere do corpo lido");
                    }

                    // Parse Message
                    Message msg = Message::fromBuffer(full);

                    // Dispatch
                    if (!dispatcher_ || !dispatcher_->dispatch(self, msg)) {
                        std::cout << "[Session] mensagem sem handler service=" 
                                  << static_cast<int>(msg.service())
                                  << " type=" << static_cast<int>(msg.msgType())
                                  << " payload=" << msg.toString() << std::endl;
                    }

                } catch (const std::exception& e) {
                    std::cerr << "[Session] erro de protocolo: " << e.what() << std::endl;
                    close();
                    return;
                }

                doReadHeader();
            }
        )
    );
}

void Session::close() {
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

} // namespace rgs::modules::network