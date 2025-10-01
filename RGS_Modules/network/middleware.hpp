#pragma once

#include "message.hpp"
#include "session.hpp"

namespace rgs::network {

// Interface para middlewares de mensagens
class Middleware {
public:
    virtual ~Middleware() = default;

    // Chamado antes de processar mensagem
    virtual void before(SessionPtr session, const Message& msg) {}

    // Chamado depois de processar mensagem
    virtual void after(SessionPtr session, const Message& msg) {}
};

} // namespace rgs::network