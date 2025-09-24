#include "network/dispatcher.hpp"
#include "network/session.hpp"
#include "network/protocol.hpp"

namespace rgs::sdk::network {

void Dispatcher::register_handler(ServiceCode svc, ServiceHandler handler) {
    handlers_[svc] = std::move(handler);
}

void Dispatcher::register_error_handler(ErrorHandler handler) {
    error_handler_ = std::move(handler);
}

void Dispatcher::dispatch(const Message& msg, Session& session) {
    // Verifica assinatura do header
    if (msg.header().magic != MAGIC_VALUE) {
        if (error_handler_) error_handler_(msg, session);
        session.close();
        return;
    }

    auto svc = static_cast<ServiceCode>(msg.header().type);
    auto it = handlers_.find(svc);
    if (it != handlers_.end()) {
        it->second(msg, session);
    } else {
        if (error_handler_) error_handler_(msg, session);
    }
}

} // namespace rgs::sdk::network
