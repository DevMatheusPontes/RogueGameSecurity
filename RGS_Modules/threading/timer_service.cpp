#include "timer_service.hpp"

namespace rgs::threading {

TimerService::TimerService(boost::asio::io_context& io) : io_(io) {}

void TimerService::schedule(std::chrono::steady_clock::duration duration,
                            std::function<void()> callback) {
    auto timer = std::make_shared<boost::asio::steady_timer>(io_, duration);
    timers_.push_back(timer);

    timer->async_wait([this, timer, callback](const boost::system::error_code& ec) {
        if (!ec) {
            callback();
        }
    });
}

void TimerService::cancel_all() {
    for (auto& t : timers_) {
        boost::system::error_code ec;
        t->cancel(ec);
    }
    timers_.clear();
}

} // namespace rgs::threading