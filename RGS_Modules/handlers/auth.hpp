#pragma once

#include "../network/handler.hpp"

namespace rgs::handlers {

struct Auth {
    static rgs::network::Handler create();
};

}