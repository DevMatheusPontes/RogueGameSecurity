#pragma once

#include <boost/thread.hpp>
#include <boost/function.hpp>
#include <vector>

namespace rgs::sdk::threads {

class TaskGroup {
public:
    TaskGroup() = default;
    ~TaskGroup();

    void run(const boost::function<void()>& task);
    void wait();

private:
    std::vector<boost::thread> tasks_;
};

} // namespace rgs::sdk::threads
