#include "network/session_manager.hpp"

namespace rgs::sdk::network {

void SessionManager::on_authenticated(const std::string& login, std::shared_ptr<Session> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[login] = std::move(session);
}

void SessionManager::add_session(const std::string& login, std::shared_ptr<Session> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[login] = std::move(session);
}

void SessionManager::remove_session(const std::string& login) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(login);
}

std::shared_ptr<Session> SessionManager::get_session(const std::string& login) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(login);
    return (it != sessions_.end()) ? it->second : nullptr;
}

void SessionManager::send_to(const std::string& login, Message& msg) {
    auto s = get_session(login);
    if (s) s->send_plain(msg);
}

void SessionManager::send_to_many(const std::vector<std::string>& logins, Message& msg) {
    for (const auto& login : logins) {
        send_to(login, msg);
    }
}

void SessionManager::broadcast(Message& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [login, session] : sessions_) {
        if (session) session->send_plain(msg);
    }
}

void SessionManager::for_each(const std::function<void(const std::string&, std::shared_ptr<Session>)>& fn) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [login, session] : sessions_) {
        fn(login, session);
    }
}

} // namespace rgs::sdk::network
