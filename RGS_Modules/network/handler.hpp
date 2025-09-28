#pragma once

#include "message.hpp"
#include "session.hpp"

namespace rgs::network {

// Assinatura padrão de um handler de serviço
using Handler = std::function<void(Session&, const Message&)>;

}