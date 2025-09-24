#include "protection/protection_pipeline.hpp"
#include <boost/log/trivial.hpp>
#include <chrono>

namespace rgs::sdk::protection {

    ProtectionPipeline::ProtectionPipeline(std::shared_ptr<Reporter> reporter, std::shared_ptr<utils::Config> config)
        : m_reporter(std::move(reporter)), m_config(std::move(config)),
          m_lastCoalescedEventTime(std::chrono::steady_clock::now()) {
        BOOST_LOG_TRIVIAL(info) << "ProtectionPipeline initialized.";
    }

    void ProtectionPipeline::onEvent(const InterceptedEvent& event) {
        if (isRateLimited()) {
            BOOST_LOG_TRIVIAL(warning) << "Event rate limited: " << event.description;
            return;
        }

        if (shouldCoalesce(event)) {
            BOOST_LOG_TRIVIAL(info) << "Event coalesced: " << event.description;
            m_lastCoalescedEventTime = std::chrono::steady_clock::now();
            m_lastCoalescedEventDescription = event.description;
            return;
        }

        m_reporter->enqueueReport(event);
    }

    bool ProtectionPipeline::shouldCoalesce(const InterceptedEvent& event) {
        bool coalesceEnabled = m_config->get<bool>("protection.coalesce_duplicates", false);
        if (!coalesceEnabled) {
            return false;
        }

        // Coalesce if the event is the same as the last coalesced event within a 1-minute window
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - m_lastCoalescedEventTime);

        if (duration.count() < 1 && event.description == m_lastCoalescedEventDescription) {
            return true;
        }

        return false;
    }

    bool ProtectionPipeline::isRateLimited() {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - m_lastEventTime);

        if (duration.count() >= 1) {
            m_eventCountInMinute = 0;
            m_lastEventTime = now;
        }

        int rateLimit = m_config->get<int>("protection.event_rate_limit_per_minute", 100);
        if (m_eventCountInMinute >= rateLimit) {
            return true;
        }

        m_eventCountInMinute++;
        return false;
    }

}
