#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <chrono>

namespace rgs::threading {

class TimerService {
public:
    TimerService(boost::asio::io_context& ctx);

    void scheduleOnce(std::chrono::milliseconds delay, std::function<void()> task);
    void scheduleRecurring(std::chrono::milliseconds interval, std::function<void()> task);

private:
    boost::asio::io_context& context_;
};

}