#include "shutdown_controller.hpp"

namespace rgs::central {

    ShutdownController::ShutdownController(boost::asio::io_context& io_context, SessionManager& sessionManager)
        : m_io_context(io_context),
          m_sessionManager(sessionManager) {}

    void ShutdownController::shutdown() {
        // This is a simplified shutdown. A real implementation would be more complex,
        // involving sending goodbye messages, waiting for responses, and handling timeouts.
        m_io_context.stop();
    }

} // namespace rgs::central
