#pragma once

#include "session_manager.hpp"
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/io_context.hpp>

namespace rgs::central {

    class HealthMonitor {
    public:
        HealthMonitor(boost::asio::io_context& io_context, SessionManager& sessionManager);

        void start();
        void stop();

    private:
        void doCheck();

        boost::asio::io_context& m_io_context;
        SessionManager& m_sessionManager;
        boost::asio::steady_timer m_timer;
        std::chrono::seconds m_checkInterval;
    };

} // namespace rgs::central
