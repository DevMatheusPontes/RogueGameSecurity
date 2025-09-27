#include "dispatcher.hpp"

namespace rgs::modules::network {

void Dispatcher::registerHandler(ServiceCode svc, Handler h) {
    handlers_[static_cast<uint8_t>(svc)] = std::move(h);
}

bool Dispatcher::dispatch(std::shared_ptr<Session> session, const Message& msg) {
    auto it = handlers_.find(static_cast<uint8_t>(msg.service()));
    if (it == handlers_.end()) return false;
    it->second(std::move(session), msg);
    return true;
}

} // namespace rgs::modules::network