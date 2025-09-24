#define BOOST_TEST_MODULE ProtectionModuleTests
#include <boost/test/unit_test.hpp>
#include "protection/event_interceptor.hpp"
#include "protection/protection_pipeline.hpp"
#include "protection/reporter.hpp"
#include "utils/config.hpp"
#include "network/session.hpp"

#include <memory>
#include <atomic>

// Mock network session for testing
class MockSession : public rgs::sdk::network::Session {
public:
    MockSession() : m_isConnected(true) {}
    bool isConnected() const override { return m_isConnected; }
    void send(const rgs::sdk::network::Message& msg) override {
        // In a real scenario, we'd store the message or verify its content
        m_sentMessages.push_back(msg);
    }
    void connect(const std::string& host, unsigned short port) override { /* no-op */ }
    void disconnect() override { /* no-op */ }

    std::vector<rgs::sdk::network::Message> m_sentMessages;
    std::atomic<bool> m_isConnected;
};

// Mock config for testing
class MockConfig : public rgs::sdk::utils::Config {
public:
    MockConfig() {
        // Default values for tests
        m_properties.put("protection.event_rate_limit_per_minute", 100);
        m_properties.put("protection.coalesce_duplicates", false);
        m_properties.put("protection.report_priority", "medium");
    }

    template<typename T>
    T get(const std::string& path, const T& defaultValue) const {
        return m_properties.get(path, defaultValue);
    }

    void set(const std::string& path, const std::string& value) {
        m_properties.put(path, value);
    }

private:
    boost::property_tree::ptree m_properties;
};

BOOST_AUTO_TEST_SUITE(EventInterceptorTests)

BOOST_AUTO_TEST_CASE(EventInterceptorBasic) {
    rgs::sdk::protection::EventInterceptor interceptor;
    std::atomic<int> eventCount = 0;

    interceptor.registerHandler([&](const rgs::sdk::protection::InterceptedEvent& event) {
        BOOST_CHECK_EQUAL(event.type, rgs::sdk::protection::EventType::MemoryViolation);
        BOOST_CHECK_EQUAL(event.description, "Test Memory Violation");
        eventCount++;
    });

    interceptor.simulateEvent(rgs::sdk::protection::EventType::MemoryViolation, "Test Memory Violation", 1);
    BOOST_CHECK_EQUAL(eventCount, 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ProtectionPipelineTests)

BOOST_AUTO_TEST_CASE(ProtectionPipelineRateLimit) {
    auto mockSession = std::make_shared<MockSession>();
    auto mockConfig = std::make_shared<MockConfig>();
    mockConfig->set("protection.event_rate_limit_per_minute", "2");

    rgs::sdk::protection::Reporter reporter(mockSession, mockConfig);
    rgs::sdk::protection::ProtectionPipeline pipeline(std::make_shared<rgs::sdk::protection::Reporter>(reporter), mockConfig);

    pipeline.onEvent({rgs::sdk::protection::EventType::ApiHook, "Hook 1", 1});
    pipeline.onEvent({rgs::sdk::protection::EventType::ApiHook, "Hook 2", 1});
    pipeline.onEvent({rgs::sdk::protection::EventType::ApiHook, "Hook 3", 1}); // Should be rate limited

    // Process the queue to send events
    reporter.processQueue();

    BOOST_CHECK_EQUAL(mockSession->m_sentMessages.size(), 2);
}

BOOST_AUTO_TEST_CASE(ProtectionPipelineCoalesce) {
    auto mockSession = std::make_shared<MockSession>();
    auto mockConfig = std::make_shared<MockConfig>();
    mockConfig->set("protection.coalesce_duplicates", "true");

    rgs::sdk::protection::Reporter reporter(mockSession, mockConfig);
    rgs::sdk::protection::ProtectionPipeline pipeline(std::make_shared<rgs::sdk::protection::Reporter>(reporter), mockConfig);

    pipeline.onEvent({rgs::sdk::protection::EventType::MemoryViolation, "Duplicate Event", 1});
    pipeline.onEvent({rgs::sdk::protection::EventType::MemoryViolation, "Duplicate Event", 1}); // Should be coalesced
    pipeline.onEvent({rgs::sdk::protection::EventType::ApiHook, "Unique Event", 1});

    reporter.processQueue();

    BOOST_CHECK_EQUAL(mockSession->m_sentMessages.size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ReporterTests)

BOOST_AUTO_TEST_CASE(ReporterEnqueueAndSend) {
    auto mockSession = std::make_shared<MockSession>();
    auto mockConfig = std::make_shared<MockConfig>();

    rgs::sdk::protection::Reporter reporter(mockSession, mockConfig);

    reporter.enqueueReport({rgs::sdk::protection::EventType::FileAccess, "File Access Detected", 1});
    reporter.enqueueReport({rgs::sdk::protection::EventType::RegistryChange, "Registry Change Detected", 1});

    reporter.processQueue();

    BOOST_CHECK_EQUAL(mockSession->m_sentMessages.size(), 2);
    BOOST_CHECK_EQUAL(mockSession->m_sentMessages[0].type, rgs::sdk::network::MessageType::DetectionReport);
    BOOST_CHECK_EQUAL(std::string(mockSession->m_sentMessages[0].payload.begin(), mockSession->m_sentMessages[0].payload.end()), "File Access Detected");
}

BOOST_AUTO_TEST_CASE(ReporterConnectionFailure) {
    auto mockSession = std::make_shared<MockSession>();
    mockSession->m_isConnected = false; // Simulate disconnected session
    auto mockConfig = std::make_shared<MockConfig>();

    rgs::sdk::protection::Reporter reporter(mockSession, mockConfig);

    reporter.enqueueReport({rgs::sdk::protection::EventType::FileAccess, "File Access Detected", 1});
    reporter.processQueue();

    BOOST_CHECK_EQUAL(mockSession->m_sentMessages.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
