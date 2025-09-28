#include "heartbeat.hpp"
#include "message.hpp"
#include "service_codes.hpp"

namespace rgs::network {

Heartbeat::Heartbeat(Session& session, threading::TimerService& timer,
                     std::chrono::milliseconds interval)
    : session_(session), timer_(timer), interval_(interval) {}

void Heartbeat::start() {
    running_ = true;
    sendPing();
}

void Heartbeat::stop() {
    running_ = false;
}

void Heartbeat::sendPing() {
    if (!running_ || !session_.isOpen()) return;

    ProtocolHeader h{1, 0, static_cast<uint16_t>(ServiceCode::Ping), 0x0001, 0, 0, 0};
    Message msg(h, {});
    session_.send(msg.encode());

    timer_.scheduleOnce(interval_, [this]() { sendPing(); });
}

}