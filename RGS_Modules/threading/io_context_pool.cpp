#include "threading/io_context_pool.hpp"

namespace rgs {
    namespace threading {

        IoContextPool::IoContextPool(std::size_t pool_size) {
            if (pool_size == 0) pool_size = 1;

            io_contexts_.reserve(pool_size);
            work_.reserve(pool_size);

            for (std::size_t i = 0; i < pool_size; ++i) {
                auto ctx = std::make_shared<boost::asio::io_context>();
                io_contexts_.push_back(ctx);
                work_.emplace_back(boost::asio::make_work_guard(*ctx));
            }
        }

        void IoContextPool::start() {
            threads_.reserve(io_contexts_.size());
            for (auto& ctx : io_contexts_) {
                threads_.emplace_back([ctx]() {
                    ctx->run();
                    });
            }
        }

        void IoContextPool::stop() {
            // Libera o work guard para cada io_context
            for (auto& w : work_) {
                w.reset();
            }
            // Solicita parada
            for (auto& ctx : io_contexts_) {
                ctx->stop();
            }
            // Aguarda todas as threads
            for (auto& t : threads_) {
                if (t.joinable()) t.join();
            }
            threads_.clear();
        }

        boost::asio::io_context& IoContextPool::get() {
            auto index = next_.fetch_add(1) % io_contexts_.size();
            return *io_contexts_[index];
        }

    } // namespace threading
} // namespace rgs