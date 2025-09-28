#include "io_context_pool.hpp"

namespace rgs::threading {

IoContextPool::IoContextPool(std::size_t poolSize) {
    contexts_.reserve(poolSize);
    guards_.reserve(poolSize);

    for (std::size_t i = 0; i < poolSize; ++i) {
        auto ctx = std::make_shared<boost::asio::io_context>();
        auto guard = std::make_shared<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(ctx->get_executor());

        contexts_.push_back(ctx);
        guards_.push_back(guard);
    }
}

void IoContextPool::start() {
    for (auto& ctx : contexts_) {
        threads_.emplace_back([ctx]() { ctx->run(); });
    }
}

void IoContextPool::stopAll() {
    for (auto& ctx : contexts_) {
        ctx->stop();
    }
}

void IoContextPool::joinAll() {
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
}

boost::asio::io_context& IoContextPool::get() {
    auto i = index_.fetch_add(1) % contexts_.size();
    return *contexts_[i];
}

}