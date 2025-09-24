#include "protection/reporter.hpp"
#include "network/message.hpp"
#include <boost/log/trivial.hpp>

namespace rgs::sdk::protection {

    Reporter::Reporter(std::shared_ptr<network::Session> session, std::shared_ptr<utils::Config> config)
        : m_session(std::move(session)), m_config(std::move(config)), m_retryCount(0) {
        BOOST_LOG_TRIVIAL(info) << "Reporter initialized.";
    }

    void Reporter::enqueueReport(const InterceptedEvent& event) {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_eventQueue.push_back(event);
        BOOST_LOG_TRIVIAL(debug) << "Enqueued event: " << event.description;
    }

    void Reporter::processQueue() {
        std::lock_guard<std::mutex> lock(m_queueMutex);

        if (!m_session || !m_session->isConnected()) {
            m_retryCount++;
            if (m_retryCount > MAX_RETRY_ATTEMPTS) {
                BOOST_LOG_TRIVIAL(error) << "Reporter: Max retry attempts reached. Dropping " << m_eventQueue.size() << " events.";
                m_eventQueue.clear(); // Drop events after max retries
                m_retryCount = 0;
            } else {
                BOOST_LOG_TRIVIAL(warning) << "Reporter: Session not connected. Retrying later (attempt " << m_retryCount << "/" << MAX_RETRY_ATTEMPTS << ").";
            }
            return;
        }

        m_retryCount = 0; // Reset retry count on successful connection

        while (!m_eventQueue.empty()) {
            sendReport(m_eventQueue.front());
            m_eventQueue.pop_front();
        }
    }

    void Reporter::sendReport(const InterceptedEvent& event) {
        network::Message reportMsg;
        reportMsg.type = network::MessageType::DetectionReport;
        
        // Serialize event into reportMsg.payload
        // For simplicity, we'll just use the description for now.
        reportMsg.payload.assign(event.description.begin(), event.description.end());

        // Get report priority from config (though this is more for the central server to interpret)
        std::string reportPriority = m_config->get<std::string>("protection.report_priority", "medium");
        BOOST_LOG_TRIVIAL(info) << "Sending report (Priority: " << reportPriority << "): " << event.description;

        // Current implementation is synchronous. For true asynchronous sending with delivery confirmation
        // and more sophisticated fallback, network::Session would need to support async operations (e.g., callbacks).
        m_session->send(reportMsg);
    }
