#pragma once

#include "../network/handler.hpp"

namespace rgs::handlers {

struct Hello {
    static rgs::network::Handler create();
};

}