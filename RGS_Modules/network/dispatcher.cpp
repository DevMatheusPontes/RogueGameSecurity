#include "dispatcher.hpp"

namespace rgs::network {

Dispatcher::Dispatcher(Router& router) : router_(router) {}

void Dispatcher::dispatch(Session& session, const std::vector<uint8_t>& raw) {
    try {
        auto msg = Message::decode(raw);
        if (!validateHeader(msg.header())) return;
        router_.route(session, msg);
    } catch (...) {
        // falha silenciosa ou log de erro
    }
}

}