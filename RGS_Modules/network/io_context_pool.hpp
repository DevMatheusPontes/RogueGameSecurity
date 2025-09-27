#pragma once
#include <boost/asio.hpp>
#include <vector>
#include <thread>
#include <memory>

namespace rgs::modules::network {

class IoContextPool {
public:
    explicit IoContextPool(std::size_t poolSize)
        : nextIdx_(0) {
        if (poolSize == 0) poolSize = 1;

        ioContexts_.reserve(poolSize);
        workGuards_.reserve(poolSize);

        for (std::size_t i = 0; i < poolSize; ++i) {
            auto ctx = std::make_shared<boost::asio::io_context>();
            ioContexts_.push_back(ctx);
            workGuards_.push_back(boost::asio::make_work_guard(*ctx));
        }
    }

    ~IoContextPool() {
        stop();
    }

    void run() {
        for (auto& ctx : ioContexts_) {
            threads_.emplace_back([ctx]() { ctx->run(); });
        }
    }

    void stop() {
        for (auto& ctx : ioContexts_) ctx->stop();
        for (auto& t : threads_) {
            if (t.joinable()) t.join();
        }
        threads_.clear();
    }

    boost::asio::io_context& next() {
        auto& ctx = *ioContexts_[nextIdx_];
        nextIdx_ = (nextIdx_ + 1) % ioContexts_.size();
        return ctx;
    }

private:
    std::vector<std::shared_ptr<boost::asio::io_context>> ioContexts_;
    std::vector<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> workGuards_;
    std::vector<std::thread> threads_;
    std::size_t nextIdx_;
};

} // namespace rgs::modules::network