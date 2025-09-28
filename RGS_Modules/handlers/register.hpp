#pragma once

#include "../network/handler.hpp"

namespace rgs::handlers {

struct Register {
    static rgs::network::Handler create();
};

}