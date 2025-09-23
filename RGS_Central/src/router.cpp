#include "router.hpp"
#include <iostream>

namespace rgs::central {

    Router::Router(sdk::network::Dispatcher& dispatcher, SessionManager& sessionManager)
        : m_dispatcher(dispatcher),
          m_sessionManager(sessionManager) {}

    void Router::registerRoutes() {
        using namespace std::placeholders;
        m_dispatcher.registerHandler(sdk::network::MessageType::Heartbeat, 
            std::bind(&Router::handleHeartbeat, this, _1, _2));
        
        // Register other handlers here
    }

    void Router::handleHeartbeat(SessionPtr session, sdk::network::Message&& message) {
        std::cout << "Heartbeat received from session " << session->getId() << std::endl;
        // Echo heartbeat back
        sdk::network::Message response(sdk::network::MessageType::HeartbeatResponse, {});
        session->asyncSend(std::move(response));
    }

} // namespace rgs::central
