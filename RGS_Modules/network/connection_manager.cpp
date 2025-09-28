#include "connection_manager.hpp"

namespace rgs::network {

void ConnectionManager::add(std::shared_ptr<Session> session) {
    std::lock_guard lock(mutex_);
    sessions_[session->id()] = session;
}

void ConnectionManager::remove(const std::string& id) {
    std::lock_guard lock(mutex_);
    sessions_.erase(id);
}

std::shared_ptr<Session> ConnectionManager::get(const std::string& id) {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(id);
    return (it != sessions_.end()) ? it->second : nullptr;
}

void ConnectionManager::broadcast(const std::vector<uint8_t>& data) {
    std::lock_guard lock(mutex_);
    for (auto& [_, session] : sessions_) {
        if (session->isOpen()) session->send(data);
    }
}

std::size_t ConnectionManager::count() const {
    std::lock_guard lock(mutex_);
    return sessions_.size();
}

}