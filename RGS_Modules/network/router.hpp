#pragma once

#include "handler.hpp"
#include "middleware.hpp"
#include <unordered_map>
#include <cstdint>

namespace rgs::network {

class Router {
public:
    void registerHandler(uint16_t serviceCode, Handler handler);
    void addMiddleware(Middleware middleware);
    void setFallback(Handler handler);

    void route(Session& session, const Message& msg) const;

private:
    std::unordered_map<uint16_t, Handler> handlers_;
    MiddlewareChain middleware_;
    Handler fallback_;
};

}