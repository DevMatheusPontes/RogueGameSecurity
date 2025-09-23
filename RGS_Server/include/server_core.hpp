#pragma once

#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/circular_buffer.hpp>
#include <thread>
#include "../../RGS_SDK/network/transport.hpp"
#include "../../RGS_SDK/network/dispatcher.hpp"

namespace rgs::server {

    class ServerCore {
    public:
        static ServerCore& getInstance();

        void start();
        void stop();

        void sendMessage(sdk::network::Message&& message);

    private:
        ServerCore();
        ~ServerCore();

        void run();

        // Core components
        boost::asio::io_context m_io_context;
        boost::asio::thread_pool m_thread_pool;
        std::unique_ptr<sdk::network::Dispatcher> m_dispatcher;
        std::unique_ptr<sdk::network::Client> m_client; // RGS_Server is a client to RGS_Central
        std::thread m_io_thread;

        // Message queues
        boost::circular_buffer<sdk::network::Message> m_sendQueue{256};
        std::mutex m_sendQueueMutex;

        std::atomic<bool> m_isRunning{false};
    };

} // namespace rgs::server
