#include "dispatcher.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

void Dispatcher::register_handler(std::uint16_t service, HandlerFunc handler) {
    handlers_[service] = std::move(handler);
}

void Dispatcher::dispatch(const Message& msg) const {
    auto it = handlers_.find(msg.header().service);
    if (it != handlers_.end()) {
        it->second(msg);
    } else {
        rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Warning,
                                           "No handler registered for service");
    }
}

} // namespace rgs::network