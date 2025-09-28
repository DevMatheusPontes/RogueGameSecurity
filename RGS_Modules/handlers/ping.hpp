#pragma once

#include "../network/handler.hpp"

namespace rgs::handlers {

struct Ping {
    static rgs::network::Handler create();
};

}