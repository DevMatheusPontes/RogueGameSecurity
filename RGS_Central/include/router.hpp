#pragma once

#include "policy_manager.hpp" // Include PolicyManager

namespace rgs::central {

    class Router {
    public:
        Router(sdk::network::Dispatcher& dispatcher, SessionManager& sessionManager, PolicyManager& policyManager);

        void registerRoutes();

    private:
        void handleHeartbeat(SessionPtr session, sdk::network::Message&& message);
        void handleDetectionReport(SessionPtr session, sdk::network::Message&& message);

        sdk::network::Dispatcher& m_dispatcher;
        SessionManager& m_sessionManager;
        PolicyManager& m_policyManager; // Add PolicyManager member
    };

} // namespace rgs::central
