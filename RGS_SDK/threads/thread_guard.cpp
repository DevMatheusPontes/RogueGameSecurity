#include "thread_guard.hpp"

namespace rgs::sdk::threads {

ThreadGuard::ThreadGuard(boost::thread& t) : thread_(t) {}

ThreadGuard::~ThreadGuard() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

} // namespace rgs::sdk::threads
