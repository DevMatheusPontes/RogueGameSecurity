#include "server_core.hpp"
#include "utils/config.hpp"
#include "hooks/hook_manager.hpp"
#include <iostream>

namespace rgs::server {

    ServerCore& ServerCore::getInstance() {
        static ServerCore instance;
        return instance;
    }

    ServerCore::ServerCore()
        : m_thread_pool(4) {}

    ServerCore::~ServerCore() {
        stop();
    }

    void ServerCore::start() {
        if (m_isRunning) return;
        m_isRunning = true;

        // Initialize HookManager
        sdk::hooks::HookManager::getInstance().initialize();

        m_io_thread = std::thread([this]() { run(); });
    }

    void ServerCore::stop() {
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

    void ServerCore::run() {
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

    void ServerCore::sendMessage(sdk::network::Message&& message) {
        if (m_isRunning && m_client && m_client->getSession() && m_client->getSession()->isConnected()) {
            m_client->getSession()->asyncSend(std::move(message));
        }
    }

} // namespace rgs::server
