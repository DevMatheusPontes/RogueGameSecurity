#pragma once

#include <boost/asio/io_context.hpp>
#include "session_manager.hpp"

namespace rgs::central {

    class ShutdownController {
    public:
        ShutdownController(boost::asio::io_context& io_context, SessionManager& sessionManager);

        void shutdown();

    private:
        boost::asio::io_context& m_io_context;
        SessionManager& m_sessionManager;
    };

} // namespace rgs::central
