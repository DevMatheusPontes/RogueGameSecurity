#pragma once

#include <vector>
#include <memory>
#include <thread>
#include <atomic>

#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

namespace rgs {
    namespace threading {

        class IoContextPool {
        public:
            explicit IoContextPool(std::size_t pool_size);
            void start();
            void stop();
            boost::asio::io_context& get();

        private:
            std::vector<std::shared_ptr<boost::asio::io_context>> io_contexts_;
            std::vector<boost::asio::executor_work_guard<
                boost::asio::io_context::executor_type
                >> work_;
            std::vector<std::thread> threads_;
            std::atomic<std::size_t> next_{ 0 };
        };

    } // namespace threading
} // namespace rgs