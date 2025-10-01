#pragma once

#include <unordered_map>
#include <functional>
#include <cstdint>
#include "message.hpp"
#include "session.hpp"

namespace rgs::network {

// Router: roteia mensagens recebidas para callbacks que conhecem a sessão.
class Router {
public:
    using RouteFunc = std::function<void(SessionPtr, const Message&)>;

    void register_route(std::uint16_t service, RouteFunc route);

    void route(SessionPtr session, const Message& msg) const;

private:
    std::unordered_map<std::uint16_t, RouteFunc> routes_;
};

} // namespace rgs::network