#include "protection/event_interceptor.hpp"
#include <algorithm>
#include <map>
#include <atomic>

namespace rgs::sdk::protection {

    EventInterceptor::EventInterceptor() : m_nextHandlerId(0) {}

    size_t EventInterceptor::registerHandler(EventHandler handler) {
        size_t id = m_nextHandlerId.fetch_add(1);
        m_handlers[id] = handler;
        return id;
    }

    void EventInterceptor::unregisterHandler(size_t handlerId) {
        m_handlers.erase(handlerId);
    }

    void EventInterceptor::simulateEvent(EventType type, std::string description, int priority) {
        InterceptedEvent event{type, std::move(description), priority};
        for (const auto& pair : m_handlers) {
            if (pair.second) {
                pair.second(event);
            }
        }
    }

}