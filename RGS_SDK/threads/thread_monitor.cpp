#include "thread_monitor.hpp"

namespace rgs::sdk::threads {

ThreadMonitor::ThreadMonitor() : running_(false) {}

ThreadMonitor::~ThreadMonitor() {
    stop();
}

void ThreadMonitor::register_thread(const std::string& name, const boost::function<void()>& task, boost::chrono::milliseconds interval) {
    MonitoredThread mt;
    mt.name = name;
    mt.task = task;
    mt.interval = interval;
    mt.active = true;

    threads_[name] = std::move(mt);
}

void ThreadMonitor::start() {
    running_ = true;
    for (auto& [name, mt] : threads_) {
        mt.thread = boost::thread([this, &mt]() { monitor_loop(mt); });
    }
}

void ThreadMonitor::stop() {
    running_ = false;
    for (auto& [name, mt] : threads_) {
        mt.active = false;
        if (mt.thread.joinable()) mt.thread.join();
    }
    threads_.clear();
}

void ThreadMonitor::monitor_loop(MonitoredThread& mt) {
    while (running_ && mt.active) {
        mt.task();
        boost::this_thread::sleep_for(mt.interval);
    }
}

} // namespace rgs::sdk::threads
