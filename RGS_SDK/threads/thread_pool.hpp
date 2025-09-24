#pragma once

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/function.hpp>
#include <boost/atomic.hpp>
#include <queue>
#include <vector>

namespace rgs::sdk::threads {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count);
    ~ThreadPool();

    void enqueue(const boost::function<void()>& task);
    void shutdown();

private:
    void worker_loop();

    std::vector<boost::thread> workers_;
    std::queue<boost::function<void()>> tasks_;
    boost::mutex queue_mutex_;
    boost::condition_variable condition_;
    boost::atomic<bool> running_;
};

} // namespace rgs::sdk::threads
