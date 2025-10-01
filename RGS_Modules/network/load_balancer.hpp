#pragma once

#include <vector>
#include <memory>
#include "session.hpp"

namespace rgs::network {

// Balanceador simples Round Robin
class LoadBalancer {
public:
    void add(SessionPtr session);
    void remove(SessionPtr session);

    SessionPtr next();

private:
    std::vector<SessionPtr> sessions_;
    std::size_t index_ = 0;
};

} // namespace rgs::network