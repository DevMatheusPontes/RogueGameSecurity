#pragma once

#include "protection/event_interceptor.hpp"
#include "protection/reporter.hpp"
#include "utils/config.hpp"

#include <memory>

namespace rgs::sdk::protection {

    class ProtectionPipeline {
    public:
        ProtectionPipeline(std::shared_ptr<Reporter> reporter, std::shared_ptr<utils::Config> config);

        void onEvent(const InterceptedEvent& event);

    private:
        bool shouldCoalesce(const InterceptedEvent& event);
        bool isRateLimited();

    private:
        std::shared_ptr<Reporter> m_reporter;
        std::shared_ptr<utils::Config> m_config;
        std::chrono::steady_clock::time_point m_lastEventTime;
        int m_eventCountInMinute;
        std::string m_lastCoalescedEventDescription;
        std::chrono::steady_clock::time_point m_lastCoalescedEventTime;
    };

}
