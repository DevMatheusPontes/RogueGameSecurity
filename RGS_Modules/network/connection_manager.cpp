#include "connection_manager.hpp"

namespace rgs::network {

void ConnectionManager::add(SessionPtr session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.insert(session);
    session->set_on_close([this](SessionPtr s) { remove(s); });
}

void ConnectionManager::remove(SessionPtr session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(session);
}

void ConnectionManager::stop_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& s : sessions_) {
        s->stop();
    }
    sessions_.clear();
}

} // namespace rgs::network