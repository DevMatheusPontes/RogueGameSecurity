#pragma once

#include <unordered_set>
#include <mutex>
#include "session.hpp"

namespace rgs::network {

// Gerencia todas as sessões ativas
class ConnectionManager {
public:
    void add(SessionPtr session);
    void remove(SessionPtr session);
    void stop_all();

private:
    std::unordered_set<SessionPtr> sessions_;
    std::mutex mutex_;
};

} // namespace rgs::network