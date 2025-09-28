#pragma once

#include <boost/asio.hpp>
#include <memory>

namespace rgs::threading {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t threadCount);
    ~ThreadPool();

    void post(std::function<void()> task);
    void stop();
    void join();

private:
    std::unique_ptr<boost::asio::thread_pool> pool_;
};

}