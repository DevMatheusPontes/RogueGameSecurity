#include "client_core.hpp"
#include "utils/config.hpp"
#include "hooks/hook_manager.hpp"
#include <iostream>

namespace rgs::client {

    ClientCore& ClientCore::getInstance() {
        static ClientCore instance;
        return instance;
    }

    ClientCore::ClientCore()
        : m_thread_pool(4),
          m_config(sdk::utils::Config::getInstancePtr()),
          m_eventInterceptor(std::make_unique<sdk::protection::EventInterceptor>()) {
        BOOST_LOG_TRIVIAL(info) << "ClientCore initialized.";
    }

    ClientCore::~ClientCore() {
        stop();
    }

    void ClientCore::start() {
        if (m_isRunning) return;
        m_isRunning = true;

        // Initialize HookManager
        sdk::hooks::HookManager::getInstance().initialize();

        m_io_thread = std::thread([this]() { run(); });

        // Initialize Reporter and ProtectionPipeline after network session is established
        // This will be done in the run() method once m_client->getSession() is available.
    }

    void ClientCore::stop() {
        if (!m_isRunning) return;
        m_isRunning = false;

        // Unregister pipeline from interceptor
        if (m_eventInterceptor && m_pipelineHandlerId != 0) {
            m_eventInterceptor->unregisterHandler(m_pipelineHandlerId);
        }

        // Shutdown HookManager
        sdk::hooks::HookManager::getInstance().shutdown();

        // Send goodbye message
        if (m_client && m_client->getSession() && m_client->getSession()->isConnected()) {
            sdk::network::Message goodbye(sdk::network::MessageType::Disconnect, {});
            // Enqueue goodbye message instead of direct send
            sendMessage(std::move(goodbye));
        }

        m_io_context.stop();
        if (m_io_thread.joinable()) {
            m_io_thread.join();
        }
        m_thread_pool.join();
    }

    void ClientCore::run() {
        auto host = m_config->get<std::string>("central.host").value_or("127.0.0.1");
        auto port = m_config->get<uint16_t>("central.port").value_or(12345);

        m_dispatcher = std::make_unique<sdk::network::Dispatcher>(m_io_context);
        m_client = std::make_unique<sdk::network::Client>(m_io_context, host, port, *m_dispatcher);

        // Initialize Reporter and ProtectionPipeline here, as m_client->getSession() is now available
        m_reporter = std::make_shared<sdk::protection::Reporter>(m_client->getSession(), m_config);
        m_protectionPipeline = std::make_unique<sdk::protection::ProtectionPipeline>(m_reporter, m_config);

        // Register ProtectionPipeline with EventInterceptor
        m_pipelineHandlerId = m_eventInterceptor->registerHandler(
            [this](const sdk::protection::InterceptedEvent& event) {
                m_protectionPipeline->onEvent(event);
            }
        );

        // Register handlers
        m_dispatcher->registerHandler(sdk::network::MessageType::HeartbeatResponse, [](auto, auto){ 
            BOOST_LOG_TRIVIAL(info) << "Heartbeat response received."; 
        });

        m_client->start();

        // Setup a timer to process the send queue and reporter queue periodically
        boost::asio::steady_timer queue_timer(m_io_context, boost::asio::chrono::milliseconds(100));
        std::function<void(const boost::system::error_code&)> timer_handler = 
            [&](const boost::system::error_code& error) {
            if (!error) {
                // Process send queue
                std::lock_guard<std::mutex> lock(m_sendQueueMutex);
                while (!m_sendQueue.empty()) {
                    if (m_client && m_client->getSession() && m_client->getSession()->isConnected()) {
                        m_client->getSession()->asyncSend(std::move(m_sendQueue.front()));
                        m_sendQueue.pop_front();
                    } else {
                        BOOST_LOG_TRIVIAL(warning) << "ClientCore: Session not connected, cannot send queued messages.";
                        break; // Stop processing if not connected
                    }
                }
                // Process reporter queue
                m_reporter->processQueue();

                queue_timer.expires_at(queue_timer.expiry() + boost::asio::chrono::milliseconds(100));
                queue_timer.async_wait(timer_handler);
            }
        };
        queue_timer.async_wait(timer_handler);

        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard(m_io_context.get_executor());
        m_io_context.run();
    }

    void ClientCore::sendMessage(sdk::network::Message&& message) {
        std::lock_guard<std::mutex> lock(m_sendQueueMutex);
        if (m_sendQueue.full()) {
            BOOST_LOG_TRIVIAL(warning) << "ClientCore: Send queue full, dropping message.";
            return;
        }
        m_sendQueue.push_back(std::move(message));
    }

} // namespace rgs::client
