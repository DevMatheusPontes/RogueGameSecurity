#pragma once

#include <vector>
#include <memory>
#include <atomic>
#include <boost/asio.hpp>

namespace rgs::threading {

class IoContextPool {
public:
    explicit IoContextPool(std::size_t poolSize);

    void start();
    void stopAll();
    void joinAll();

    boost::asio::io_context& get();

private:
    std::vector<std::shared_ptr<boost::asio::io_context>> contexts_;
    std::vector<std::shared_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>> guards_;
    std::vector<std::thread> threads_;
    std::atomic<std::size_t> index_{0};
};

}