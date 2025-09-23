#pragma once

#include "message.hpp"
#include "protocol.hpp"

#include <boost/asio.hpp>
#include <boost/circular_buffer.hpp>
#include <memory>
#include <queue>
#include <mutex>

namespace rgs::sdk::network {

    using boost::asio::ip::tcp;

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(tcp::socket socket, 
                 std::chrono::seconds heartbeat_interval,
                 std::chrono::seconds inactivity_timeout);
        ~Session();

        uint64_t getId() const { return m_id; }

        void start();
        void stop();

        void asyncSend(Message&& message);

        bool isConnected() const;

        // Handlers for dispatcher
        using MessageHandler = std::function<void(Message&&)>;
        void setMessageHandler(MessageHandler handler) { m_messageHandler = handler; }

        using DisconnectHandler = std::function<void()>;
        void setDisconnectHandler(DisconnectHandler handler) { m_disconnectHandler = handler; }

    private:
        void doReadHeader();
        void doReadPayload(std::size_t payloadSize);
        void doWrite();

        void startHeartbeat();
        void onHeartbeat(const boost::system::error_code& ec);
        void checkDeadline();

        static std::atomic<uint64_t> s_nextId;
        const uint64_t m_id;

        tcp::socket m_socket;
        boost::asio::strand<boost::asio::io_context::executor_type> m_strand;
        boost::asio::steady_timer m_heartbeatTimer;
        boost::asio::steady_timer m_deadlineTimer;

        // Double buffer for reading
        std::vector<std::byte> m_readBuffer;
        ProtocolHeader m_readHeader{};

        // Queue for outgoing messages with priorities
        boost::circular_buffer<Message> m_writeQueue_high{128};
        boost::circular_buffer<Message> m_writeQueue_medium{256};
        boost::circular_buffer<Message> m_writeQueue_low{512};
        std::mutex m_queueMutex;

        MessageHandler m_messageHandler;
        DisconnectHandler m_disconnectHandler;

        std::chrono::seconds m_heartbeat_interval;
        std::chrono::seconds m_inactivity_timeout;

        std::atomic<bool> m_isConnected{true};
    };

} // namespace rgs::sdk::network
