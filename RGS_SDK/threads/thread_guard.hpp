#pragma once

#include <boost/thread.hpp>

namespace rgs::sdk::threads {

class ThreadGuard {
public:
    explicit ThreadGuard(boost::thread& t);
    ~ThreadGuard();

    // Não copiável
    ThreadGuard(const ThreadGuard&) = delete;
    ThreadGuard& operator=(const ThreadGuard&) = delete;

private:
    boost::thread& thread_;
};

} // namespace rgs::sdk::threads
