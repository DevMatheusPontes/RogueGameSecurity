#pragma once

#include "message.hpp"
#include "session.hpp"
#include <functional>
#include <vector>

namespace rgs::network {

// Middleware: função que pode bloquear ou permitir execução
using Middleware = std::function<bool(Session&, const Message&)>;

class MiddlewareChain {
public:
    void add(Middleware m);
    bool execute(Session& session, const Message& msg) const;

private:
    std::vector<Middleware> chain_;
};

}