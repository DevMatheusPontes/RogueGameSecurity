#pragma once

#include <chrono>
#include <memory>
#include "session.hpp"
#include "timer_service.hpp"

namespace rgs::network {

class Heartbeat {
public:
    Heartbeat(Session& session, threading::TimerService& timer,
              std::chrono::milliseconds interval = std::chrono::seconds(10));

    void start();
    void stop();

private:
    void sendPing();

    Session& session_;
    threading::TimerService& timer_;
    std::chrono::milliseconds interval_;
    bool running_{false};
};

}