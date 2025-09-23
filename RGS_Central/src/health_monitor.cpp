#include "health_monitor.hpp"
#include "policy_manager.hpp"

namespace rgs::central {

    HealthMonitor::HealthMonitor(boost::asio::io_context& io_context, SessionManager& sessionManager)
        : m_io_context(io_context),
          m_sessionManager(sessionManager),
          m_timer(io_context) {
        auto& policy = PolicyManager::getInstance();
        m_checkInterval = std::chrono::seconds(policy.get<long>("central.health_check_interval_seconds", 10));
    }

    void HealthMonitor::start() {
        doCheck();
    }

    void HealthMonitor::stop() {
        m_timer.cancel();
    }

    void HealthMonitor::doCheck() {
        // In a real implementation, we would iterate through sessions
        // and check their status (e.g., last heartbeat time).
        // For now, this is a placeholder.

        m_timer.expires_after(m_checkInterval);
        m_timer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec) {
                doCheck();
            }
        });
    }

} // namespace rgs::central
