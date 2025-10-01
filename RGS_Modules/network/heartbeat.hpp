#pragma once

#include <chrono>
#include <unordered_map>
#include <memory>
#include "session.hpp"

namespace rgs::network {

class Heartbeat {
public:
    explicit Heartbeat(std::chrono::seconds timeout);

    void mark_alive(SessionPtr session);
    void check_timeouts();

private:
    std::chrono::seconds timeout_;
    std::unordered_map<SessionPtr, std::chrono::steady_clock::time_point> last_seen_;
};

} // namespace rgs::network