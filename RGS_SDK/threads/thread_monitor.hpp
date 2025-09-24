#pragma once

#include <boost/thread.hpp>
#include <boost/chrono.hpp>
#include <boost/function.hpp>
#include <unordered_map>
#include <string>
#include <atomic>

namespace rgs::sdk::threads {

class ThreadMonitor {
public:
    ThreadMonitor();
    ~ThreadMonitor();

    void register_thread(const std::string& name, const boost::function<void()>& task, boost::chrono::milliseconds interval);
    void start();
    void stop();

private:
    struct MonitoredThread {
        std::string name;
        boost::function<void()> task;
        boost::chrono::milliseconds interval;
        boost::thread thread;
        std::atomic<bool> active;
    };

    void monitor_loop(MonitoredThread& mt);

    std::unordered_map<std::string, MonitoredThread> threads_;
    std::atomic<bool> running_;
};

} // namespace rgs::sdk::threads
