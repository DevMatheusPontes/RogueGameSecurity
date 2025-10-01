#include "router.hpp"
#include "utils/logger.hpp"

namespace rgs::network {

void Router::register_route(std::uint16_t service, RouteFunc route) {
    routes_[service] = std::move(route);
}

void Router::route(SessionPtr session, const Message& msg) const {
    auto it = routes_.find(msg.header().service);
    if (it != routes_.end()) {
        it->second(session, msg);
    } else {
        rgs::utils::Logger::instance().log(rgs::utils::LogLevel::Warning,
                                           "No route registered for service");
    }
}

} // namespace rgs::network