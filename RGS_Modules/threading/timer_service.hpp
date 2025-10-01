#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <chrono>

namespace rgs::threading {

// Serviço de timers baseado em Boost.Asio.
class TimerService {
public:
    explicit TimerService(boost::asio::io_context& io);

    // Agenda uma função após 'duration'.
    void schedule(std::chrono::steady_clock::duration duration,
                  std::function<void()> callback);

    // Cancela todos os timers ativos.
    void cancel_all();

private:
    boost::asio::io_context& io_;
    std::vector<std::shared_ptr<boost::asio::steady_timer>> timers_;
};

} // namespace rgs::threading