#pragma once

#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/circular_buffer.hpp>
#include <thread>
#include "../../RGS_SDK/protection/event_interceptor.hpp"
#include "../../RGS_SDK/protection/protection_pipeline.hpp"
#include "../../RGS_SDK/protection/reporter.hpp"
#include "../../RGS_SDK/utils/config.hpp"

namespace rgs::client {

    class ClientCore {
    public:
        static ClientCore& getInstance();

        void start();
        void stop();

        void sendMessage(sdk::network::Message&& message);

    private:
        ClientCore();
        ~ClientCore();

        void run();

        // Core components
        boost::asio::io_context m_io_context;
        boost::asio::thread_pool m_thread_pool;
        std::unique_ptr<sdk::network::Dispatcher> m_dispatcher;
        std::unique_ptr<sdk::network::Client> m_client;
        std::thread m_io_thread;

        // Protection modules
        std::shared_ptr<sdk::utils::Config> m_config;
        std::unique_ptr<sdk::protection::EventInterceptor> m_eventInterceptor;
        std::shared_ptr<sdk::protection::Reporter> m_reporter;
        std::unique_ptr<sdk::protection::ProtectionPipeline> m_protectionPipeline;
        size_t m_pipelineHandlerId; // To unregister the pipeline from the interceptor

        // Message queues
        boost::circular_buffer<sdk::network::Message> m_sendQueue{256};
        std::mutex m_sendQueueMutex;

        std::atomic<bool> m_isRunning{false};
    };

} // namespace rgs::client
