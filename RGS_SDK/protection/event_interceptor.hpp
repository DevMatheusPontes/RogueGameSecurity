#pragma once

#include <functional>
#include <string>
#include <vector>

namespace rgs::sdk::protection {

    enum class EventType {
        Unknown,
        MemoryViolation,
        ApiHook,
        FileAccess,
        RegistryChange
    };

    struct InterceptedEvent {
        EventType type;
        std::string description;
        int priority;
    };

    class EventInterceptor {
    public:
        using EventHandler = std::function<void(const InterceptedEvent&)>;

        void registerHandler(EventHandler handler);
        void unregisterHandler(const EventHandler& handler);

        void simulateEvent(EventType type, std::string description, int priority);

    private:
        std::map<size_t, EventHandler> m_handlers;
        std::atomic<size_t> m_nextHandlerId;
    };

}
