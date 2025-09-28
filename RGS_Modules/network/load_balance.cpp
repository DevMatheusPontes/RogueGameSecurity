#include "load_balancer.hpp"

namespace rgs::network {

LoadBalancer::LoadBalancer() {}

void LoadBalancer::addTarget(const std::string& host, uint16_t port) {
    std::lock_guard lock(mutex_);
    targets_.emplace_back(host, port);
}

void LoadBalancer::clear() {
    std::lock_guard lock(mutex_);
    targets_.clear();
    index_ = 0;
}

std::pair<std::string, uint16_t> LoadBalancer::next() {
    std::lock_guard lock(mutex_);
    if (targets_.empty()) return {"", 0};
    auto i = index_.fetch_add(1) % targets_.size();
    return targets_[i];
}

std::size_t LoadBalancer::size() const {
    std::lock_guard lock(mutex_);
    return targets_.size();
}

}