#include "task_group.hpp"

namespace rgs::sdk::threads {

TaskGroup::~TaskGroup() {
    wait();
}

void TaskGroup::run(const boost::function<void()>& task) {
    tasks_.emplace_back(task);
}

void TaskGroup::wait() {
    for (auto& t : tasks_) {
        if (t.joinable()) t.join();
    }
    tasks_.clear();
}

} // namespace rgs::sdk::threads
