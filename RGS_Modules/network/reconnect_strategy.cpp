#include "reconnect_strategy.hpp"

namespace rgs::network {

ReconnectStrategy::ReconnectStrategy(std::size_t maxAttempts,
                                     std::chrono::milliseconds baseDelay,
                                     bool exponential)
    : maxAttempts_(maxAttempts), baseDelay_(baseDelay), exponential_(exponential) {}

bool ReconnectStrategy::shouldRetry(std::size_t attempt) const {
    return attempt < maxAttempts_;
}

std::chrono::milliseconds ReconnectStrategy::nextDelay(std::size_t attempt) const {
    if (exponential_) {
        return baseDelay_ * (1 << attempt); // backoff exponencial
    }
    return baseDelay_; // intervalo fixo
}

}