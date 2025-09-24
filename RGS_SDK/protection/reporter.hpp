#pragma once

#include "protection/event_interceptor.hpp"
#include "network/session.hpp"
#include "utils/config.hpp"

#include <memory>
#include <deque>
#include <mutex>

namespace rgs::sdk::protection {

    class Reporter {
    public:
        Reporter(std::shared_ptr<network::Session> session, std::shared_ptr<utils::Config> config);

        void enqueueReport(const InterceptedEvent& event);
        void processQueue();

    private:
        void sendReport(const InterceptedEvent& event);

    private:
        std::shared_ptr<network::Session> m_session;
        std::shared_ptr<utils::Config> m_config;
        std::deque<InterceptedEvent> m_eventQueue;
        std::mutex m_queueMutex;
        int m_retryCount;
        static const int MAX_RETRY_ATTEMPTS = 3;
    };

}
