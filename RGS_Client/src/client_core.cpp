#include "client_core.hpp"
#include "../../RGS_SDK/utils/config.hpp"
#include "../../RGS_SDK/hooks/hook_manager.hpp"
#include <iostream>

namespace rgs::client {

    ClientCore& ClientCore::getInstance() {
        static ClientCore instance;
        return instance;
    }

    ClientCore::ClientCore()
        : m_thread_pool(4) {}

    ClientCore::~ClientCore() {
        stop();
    }

    void ClientCore::start() {
        if (m_isRunning) return;
        m_isRunning = true;

        // Initialize HookManager
        sdk::hooks::HookManager::getInstance().initialize();

        m_io_thread = std::thread([this]() { run(); });
    }

    void ClientCore::stop() {
        if (!m_isRunning) return;
        m_isRunning = false;

        // Shutdown HookManager
        sdk::hooks::HookManager::getInstance().shutdown();

        // Send goodbye message
        if (m_client && m_client->getSession() && m_client->getSession()->isConnected()) {
            sdk::network::Message goodbye(sdk::network::MessageType::Disconnect, {});
            m_client->getSession()->asyncSend(std::move(goodbye));
        }

        m_io_context.stop();
        if (m_io_thread.joinable()) {
            m_io_thread.join();
        }
        m_thread_pool.join();
    }

    void ClientCore::run() {
        auto& config = sdk::utils::Config::getInstance();
        auto host = config.get<std::string>("central.host").value_or("127.0.0.1");
        auto port = config.get<uint16_t>("central.port").value_or(12345);

        m_dispatcher = std::make_unique<sdk::network::Dispatcher>(m_io_context);
        m_client = std::make_unique<sdk::network::Client>(m_io_context, host, port, *m_dispatcher);

        // Register handlers
        m_dispatcher->registerHandler(sdk::network::MessageType::HeartbeatResponse, [](auto, auto){ 
            std::cout << "Heartbeat response received." << std::endl; 
        });

        m_client->start();

        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard(m_io_context.get_executor());
        m_io_context.run();
    }

    void ClientCore::sendMessage(sdk::network::Message&& message) {
        // In a real implementation, this would push to a queue that the IO thread would process.
        if (m_isRunning && m_client && m_client->getSession() && m_client->getSession()->isConnected()) {
            m_client->getSession()->asyncSend(std::move(message));
        }
    }

} // namespace rgs::client
