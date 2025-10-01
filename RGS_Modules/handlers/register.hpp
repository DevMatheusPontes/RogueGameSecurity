#pragma once

#include "network/message.hpp"
#include "network/session.hpp"

namespace rgs::handlers {

class RegisterHandler {
public:
    static void handle(rgs::network::SessionPtr session, const rgs::network::Message& msg);
};

} // namespace rgs::handlers