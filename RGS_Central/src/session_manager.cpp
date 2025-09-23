#include "session_manager.hpp"

namespace rgs::central {

    void SessionManager::add(const SessionPtr& session) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sessions.insert(session);
    }

    void SessionManager::remove(const SessionPtr& session) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sessions.get<tag_ptr>().erase(session);
    }

    SessionPtr SessionManager::find(uint64_t sessionId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto& index = m_sessions.get<tag_id>();
        auto it = index.find(sessionId);

        if (it != index.end()) {
            return *it;
        }
        return nullptr;
    }

    size_t SessionManager::count() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.size();
    }

} // namespace rgs::central
