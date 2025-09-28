#pragma once

#include "router.hpp"
#include "message.hpp"
#include "session.hpp"

namespace rgs::network {

class Dispatcher {
public:
    explicit Dispatcher(Router& router);

    void dispatch(Session& session, const std::vector<uint8_t>& raw);

private:
    Router& router_;
};

}