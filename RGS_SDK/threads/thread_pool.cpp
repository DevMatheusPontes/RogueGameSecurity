#include "thread_pool.hpp"

namespace rgs::sdk::threads {

ThreadPool::ThreadPool(std::size_t thread_count) : running_(true) {
    for (std::size_t i = 0; i < thread_count; ++i) {
        workers_.emplace_back(boost::bind(&ThreadPool::worker_loop, this));
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::enqueue(const boost::function<void()>& task) {
    {
        boost::unique_lock<boost::mutex> lock(queue_mutex_);
        tasks_.push(task);
    }
    condition_.notify_one();
}

void ThreadPool::shutdown() {
    running_.store(false);
    condition_.notify_all();

    for (auto& thread : workers_) {
        if (thread.joinable()) thread.join();
    }
}

void ThreadPool::worker_loop() {
    while (running_.load()) {
        boost::function<void()> task;

        {
            boost::unique_lock<boost::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this]() {
                return !tasks_.empty() || !running_.load();
            });

            if (!running_.load() && tasks_.empty()) return;

            task = tasks_.front();
            tasks_.pop();
        }

        if (task) task();
    }
}

} // namespace rgs::sdk::threads
