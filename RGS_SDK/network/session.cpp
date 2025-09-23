#include "session.hpp"
#include "../security/nonce.hpp"
#include "../security/hash.hpp"
#include <boost/asio/post.hpp>
#include <boost/bind/bind.hpp>

namespace rgs::sdk::network {

    std::atomic<uint64_t> Session::s_nextId = 1;

    Session::Session(tcp::socket socket,
                     std::chrono::seconds heartbeat_interval,
                     std::chrono::seconds inactivity_timeout)
        : m_id(s_nextId++),
          m_socket(std::move(socket)),
          m_strand(m_socket.get_executor()),
          m_heartbeatTimer(m_socket.get_executor()),
          m_deadlineTimer(m_socket.get_executor()),
          m_heartbeat_interval(heartbeat_interval),
          m_inactivity_timeout(inactivity_timeout) {
        m_readBuffer.resize(4096); // Default read buffer size
    }

    Session::~Session() {
        stop();
    }

    void Session::start() {
        m_isConnected = true;
        doReadHeader();
        startHeartbeat();
        checkDeadline();
    }

    void Session::stop() {
        if (!m_isConnected.exchange(false)) {
            return;
        }

        boost::asio::post(m_strand, [self = shared_from_this()]() {
            self->m_heartbeatTimer.cancel();
            self->m_deadlineTimer.cancel();
            boost::system::error_code ec;
            self->m_socket.shutdown(tcp::socket::shutdown_both, ec);
            self->m_socket.close(ec);
            if (self->m_disconnectHandler) {
                self->m_disconnectHandler();
            }
        });
    }

    bool Session::isConnected() const {
        return m_isConnected;
    }

    void Session::asyncSend(Message&& message) {
        message.getHeader().nonce = security::NonceManager::getInstance().newNonce();
        message.getHeader().crc32 = security::computeCrc32(message.getPayload());

        boost::asio::post(m_strand, [self = shared_from_this(), message = std::move(message)]() mutable {
            bool write_in_progress = false;
            {
                std::lock_guard<std::mutex> lock(self->m_queueMutex);
                if (static_cast<uint16_t>(message.getHeader().flags) & static_cast<uint16_t>(MessageFlags::HighPriority)) {
                     write_in_progress = !self->m_writeQueue_high.empty() || !self->m_writeQueue_medium.empty() || !self->m_writeQueue_low.empty();
                    self->m_writeQueue_high.push_back(std::move(message));
                } else {
                    write_in_progress = !self->m_writeQueue_high.empty() || !self->m_writeQueue_medium.empty() || !self->m_writeQueue_low.empty();
                    self->m_writeQueue_medium.push_back(std::move(message));
                }
            }

            if (!write_in_progress) {
                self->doWrite();
            }
        });
    }

    void Session::doReadHeader() {
        auto self = shared_from_this();
        boost::asio::async_read(m_socket, boost::asio::buffer(&m_readHeader, sizeof(ProtocolHeader)),
            boost::asio::bind_executor(m_strand, [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && validateHeader(m_readHeader)) {
                    if (security::NonceManager::getInstance().isReplay(m_id, m_readHeader.nonce)) {
                        stop(); // Replay attack detected
                        return;
                    }

                    if (m_readHeader.length > 0) {
                        doReadPayload(m_readHeader.length);
                    } else {
                        Message msg(m_readHeader.type, {});
                        msg.getHeader() = m_readHeader;
                        if (m_messageHandler) m_messageHandler(std::move(msg));
                        doReadHeader();
                    }
                } else {
                    stop();
                }
            }));
    }

    void Session::doReadPayload(std::size_t payloadSize) {
        if (payloadSize > m_readBuffer.size()) {
            m_readBuffer.resize(payloadSize);
        }

        auto self = shared_from_this();
        boost::asio::async_read(m_socket, boost::asio::buffer(m_readBuffer.data(), payloadSize),
            boost::asio::bind_executor(m_strand, [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (!ec) {
                    std::vector<std::byte> payload(bytes_transferred);
                    std::memcpy(payload.data(), m_readBuffer.data(), bytes_transferred);

                    if (security::verifyCrc32(payload, m_readHeader.crc32)) {
                        Message msg(m_readHeader.type, std::move(payload));
                        msg.getHeader() = m_readHeader;
                        if (m_messageHandler) m_messageHandler(std::move(msg));
                        doReadHeader();
                    } else {
                        stop(); // CRC mismatch
                    }
                } else {
                    stop();
                }
            }));
    }

    void Session::doWrite() {
        auto self = shared_from_this();
        boost::asio::post(m_strand, [this, self](){
            std::lock_guard<std::mutex> lock(m_queueMutex);
            if (m_writeQueue_high.empty() && m_writeQueue_medium.empty() && m_writeQueue_low.empty()) {
                return;
            }

            boost::circular_buffer<Message>* currentQueue = nullptr;
            if (!m_writeQueue_high.empty()) currentQueue = &m_writeQueue_high;
            else if (!m_writeQueue_medium.empty()) currentQueue = &m_writeQueue_medium;
            else if (!m_writeQueue_low.empty()) currentQueue = &m_writeQueue_low;

            if (!currentQueue) return;

            Message& msg = currentQueue->front();
            
            std::vector<boost::asio::const_buffer> buffers;
            buffers.push_back(boost::asio::buffer(&msg.getHeader(), sizeof(ProtocolHeader)));
            buffers.push_back(boost::asio::buffer(msg.getPayload()));

            boost::asio::async_write(m_socket, buffers,
                boost::asio::bind_executor(m_strand, [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec) {
                        {
                            std::lock_guard<std::mutex> lock(m_queueMutex);
                            if (!m_writeQueue_high.empty()) m_writeQueue_high.pop_front();
                            else if (!m_writeQueue_medium.empty()) m_writeQueue_medium.pop_front();
                            else if (!m_writeQueue_low.empty()) m_writeQueue_low.pop_front();
                        }
                        if (m_isConnected) {
                           doWrite();
                        }
                    } else {
                        stop();
                    }
                }));
        });
    }

    void Session::startHeartbeat() {
        m_heartbeatTimer.expires_after(m_heartbeat_interval);
        m_heartbeatTimer.async_wait(boost::asio::bind_executor(m_strand, 
            boost::bind(&Session::onHeartbeat, shared_from_this(), boost::asio::placeholders::error)));
    }

    void Session::onHeartbeat(const boost::system::error_code& ec) {
        if (ec) return;

        if (m_isConnected) {
            asyncSend(Message(MessageType::Heartbeat, {}));
            startHeartbeat();
        }
    }

    void Session::checkDeadline() {
        m_deadlineTimer.expires_after(m_inactivity_timeout);
        m_deadlineTimer.async_wait(boost::asio::bind_executor(m_strand, [this, self = shared_from_this()](const boost::system::error_code& ec){
            if(ec) return;
            stop();
        }));
    }

} // namespace rgs::sdk::network