#pragma once

#include "message.hpp"
#include "session.hpp"

namespace rgs::network {

// Interface base para handlers de mensagens.
// Cada handler deve implementar 'handle' recebendo a sessão e a mensagem.
class IHandler {
public:
    virtual ~IHandler() = default;
    virtual void handle(SessionPtr session, const Message& msg) = 0;
};

} // namespace rgs::network