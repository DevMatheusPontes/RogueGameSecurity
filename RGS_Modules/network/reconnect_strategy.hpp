#pragma once

#include <chrono>
#include <functional>

namespace rgs::network {

class ReconnectStrategy {
public:
    ReconnectStrategy(std::size_t maxAttempts,
                      std::chrono::milliseconds baseDelay,
                      bool exponential = true);

    bool shouldRetry(std::size_t attempt) const;
    std::chrono::milliseconds nextDelay(std::size_t attempt) const;

private:
    std::size_t maxAttempts_;
    std::chrono::milliseconds baseDelay_;
    bool exponential_;
};

}