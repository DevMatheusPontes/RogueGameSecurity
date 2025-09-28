#include "timer_service.hpp"

namespace rgs::threading {

TimerService::TimerService(boost::asio::io_context& ctx) : context_(ctx) {}

void TimerService::scheduleOnce(std::chrono::milliseconds delay, std::function<void()> task) {
    auto timer = std::make_shared<boost::asio::steady_timer>(context_, delay);
    timer->async_wait([task, timer](const boost::system::error_code&) {
        task();
    });
}

void TimerService::scheduleRecurring(std::chrono::milliseconds interval, std::function<void()> task) {
    auto timer = std::make_shared<boost::asio::steady_timer>(context_, interval);
    std::function<void()> wrapper;

    wrapper = [timer, interval, task, wrapper]() mutable {
        task();
        timer->expires_after(interval);
        timer->async_wait([wrapper](const boost::system::error_code&) {
            wrapper();
        });
    };

    timer->async_wait([wrapper](const boost::system::error_code&) {
        wrapper();
    });
}

}