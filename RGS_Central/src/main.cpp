#include <iostream>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/log/trivial.hpp>

#include "policy_manager.hpp"
#include "session_manager.hpp"
#include "health_monitor.hpp"
#include "router.hpp"
#include "shutdown_controller.hpp"
#include "../../RGS_SDK/network/transport.hpp"
#include "../../RGS_SDK/network/dispatcher.hpp"

int main() {
    // Load configuration
    auto& policyManager = rgs::central::PolicyManager::getInstance();
    if (!policyManager.load("config.json")) {
        BOOST_LOG_TRIVIAL(fatal) << "Failed to load config.json";
        return 1;
    }

    try {
        boost::asio::io_context io_context;

        // Create central components
        rgs::central::SessionManager sessionManager;
        rgs::sdk::network::Dispatcher dispatcher(io_context);
        rgs::central::Router router(dispatcher, sessionManager, policyManager);
        rgs::central::HealthMonitor healthMonitor(io_context, sessionManager);
        rgs::central::ShutdownController shutdownController(io_context, sessionManager);

        // Register message handlers
        router.registerRoutes();

        // Start the server
        auto port = policyManager.get<uint16_t>("central.port", 12345);
        rgs::sdk::network::Server server(io_context, port, dispatcher);
        
        server.setSessionHandler([&sessionManager, &dispatcher](std::shared_ptr<rgs::sdk::network::Session> session) {
            sessionManager.add(session);
            BOOST_LOG_TRIVIAL(info) << "New session connected: " << session->getId();

            session->setDisconnectHandler([&sessionManager, session](){
                sessionManager.remove(session);
                BOOST_LOG_TRIVIAL(info) << "Session disconnected: " << session->getId();
            });

            session->setMessageHandler([&dispatcher, session](rgs::sdk::network::Message&& msg){
                dispatcher.dispatch(session, std::move(msg));
            });
        });

        server.start();
        healthMonitor.start();

        BOOST_LOG_TRIVIAL(info) << "RGS_Central started on port " << port;

        // Wait for a signal to shut down
        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int) {
            shutdownController.shutdown();
        });

        io_context.run();

        BOOST_LOG_TRIVIAL(info) << "RGS_Central shut down gracefully.";
    }
    catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(fatal) << "Exception: " << e.what();
        return 1;
    }

    return 0;
}