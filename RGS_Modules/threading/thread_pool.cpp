#include "thread_pool.hpp"

namespace rgs::threading {

ThreadPool::ThreadPool(std::size_t threadCount) {
    pool_ = std::make_unique<boost::asio::thread_pool>(threadCount);
}

ThreadPool::~ThreadPool() {
    stop();
    join();
}

void ThreadPool::post(std::function<void()> task) {
    boost::asio::post(*pool_, std::move(task));
}

void ThreadPool::stop() {
    pool_->stop();
}

void ThreadPool::join() {
    pool_->join();
}

}