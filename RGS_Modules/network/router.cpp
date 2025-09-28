#include "router.hpp"

namespace rgs::network {

void Router::registerHandler(uint16_t serviceCode, Handler handler) {
    handlers_[serviceCode] = std::move(handler);
}

void Router::addMiddleware(Middleware middleware) {
    middleware_.add(std::move(middleware));
}

void Router::setFallback(Handler handler) {
    fallback_ = std::move(handler);
}

void Router::route(Session& session, const Message& msg) const {
    if (!middleware_.execute(session, msg)) return;

    auto code = msg.header().serviceCode;
    auto it = handlers_.find(code);

    if (it != handlers_.end()) {
        it->second(session, msg);
    } else if (fallback_) {
        fallback_(session, msg);
    }
}

}