#include "heartbeat.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

Heartbeat::Heartbeat(std::chrono::seconds timeout) : timeout_(timeout) {}

void Heartbeat::mark_alive(SessionPtr session) {
    last_seen_[session] = std::chrono::steady_clock::now();
}

void Heartbeat::check_timeouts() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = last_seen_.begin(); it != last_seen_.end();) {
        if (now - it->second > timeout_) {
            rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Warning,
                                               "Session timed out");
            it->first->stop();
            it = last_seen_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace rgs::network