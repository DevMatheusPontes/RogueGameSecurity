#pragma once

#include "session_manager.hpp"
#include "../../RGS_SDK/network/dispatcher.hpp"

namespace rgs::central {

    class Router {
    public:
        Router(sdk::network::Dispatcher& dispatcher, SessionManager& sessionManager);

        void registerRoutes();

    private:
        // Example handler
        void handleHeartbeat(SessionPtr session, sdk::network::Message&& message);

        sdk::network::Dispatcher& m_dispatcher;
        SessionManager& m_sessionManager;
    };

} // namespace rgs::central
