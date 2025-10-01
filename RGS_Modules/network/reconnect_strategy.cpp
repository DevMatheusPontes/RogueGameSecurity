#include "reconnect_strategy.hpp"

namespace rgs::network {

ReconnectStrategy::ReconnectStrategy(std::chrono::milliseconds base_delay,
                                     std::chrono::milliseconds max_delay)
    : base_(base_delay), max_(max_delay), current_(base_delay) {}

std::chrono::milliseconds ReconnectStrategy::next_delay() {
    auto delay = current_;
    current_ = std::min(current_ * 2, max_);
    return delay;
}

void ReconnectStrategy::reset() {
    current_ = base_;
}

} // namespace rgs::network