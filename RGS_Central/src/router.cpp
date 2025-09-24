#include "router.hpp"
#include <boost/log/trivial.hpp>

namespace rgs::central {

    Router::Router(sdk::network::Dispatcher& dispatcher, SessionManager& sessionManager, PolicyManager& policyManager)
        : m_dispatcher(dispatcher),
          m_sessionManager(sessionManager),
          m_policyManager(policyManager) {
        BOOST_LOG_TRIVIAL(info) << "Router initialized.";
    }

    void Router::registerRoutes() {
        using namespace std::placeholders;
        m_dispatcher.registerHandler(sdk::network::MessageType::Heartbeat, 
            std::bind(&Router::handleHeartbeat, this, _1, _2));
        
        m_dispatcher.registerHandler(sdk::network::MessageType::DetectionReport,
            std::bind(&Router::handleDetectionReport, this, _1, _2));

        BOOST_LOG_TRIVIAL(info) << "Routes registered.";
    }

    void Router::handleHeartbeat(SessionPtr session, sdk::network::Message&& message) {
        BOOST_LOG_TRIVIAL(info) << "Heartbeat received from session " << session->getId();
        // Echo heartbeat back
        sdk::network::Message response(sdk::network::MessageType::HeartbeatResponse, {});
        session->asyncSend(std::move(response));
    }

    void Router::handleDetectionReport(SessionPtr session, sdk::network::Message&& message) {
        std::string reportContent(message.payload.begin(), message.payload.end());
        BOOST_LOG_TRIVIAL(warning) << "Detection Report received from session " << session->getId() << ": " << reportContent;

        // Example: Interact with PolicyManager based on the report content
        // For now, just a placeholder. Real logic would involve parsing the report
        // and applying specific policies.
        if (reportContent.find("MemoryViolation") != std::string::npos) {
            BOOST_LOG_TRIVIAL(error) << "PolicyManager: Potential memory violation detected from session " << session->getId();
            // m_policyManager.applyPolicy(session->getId(), PolicyType::MemoryViolation);
        }

        // Acknowledge the report (optional, depending on protocol)
        sdk::network::Message ack(sdk::network::MessageType::Acknowledgement, {});
        session->asyncSend(std::move(ack));
    }

} // namespace rgs::central