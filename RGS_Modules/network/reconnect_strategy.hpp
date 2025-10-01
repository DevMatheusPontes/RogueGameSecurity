#pragma once

#include <chrono>

namespace rgs::network {

// Estratégia de reconexão com backoff exponencial simples
class ReconnectStrategy {
public:
    explicit ReconnectStrategy(std::chrono::milliseconds base_delay,
                               std::chrono::milliseconds max_delay);

    std::chrono::milliseconds next_delay();
    void reset();

private:
    std::chrono::milliseconds base_;
    std::chrono::milliseconds max_;
    std::chrono::milliseconds current_;
};

} // namespace rgs::network