#include "load_balancer.hpp"

namespace rgs::network {

void LoadBalancer::add(SessionPtr session) {
    sessions_.push_back(session);
}

void LoadBalancer::remove(SessionPtr session) {
    sessions_.erase(std::remove(sessions_.begin(), sessions_.end(), session), sessions_.end());
}

SessionPtr LoadBalancer::next() {
    if (sessions_.empty()) return nullptr;
    if (index_ >= sessions_.size()) index_ = 0;
    return sessions_[index_++];
}

} // namespace rgs::network