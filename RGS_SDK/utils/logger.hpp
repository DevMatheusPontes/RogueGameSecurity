#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace rgs::sdk::utils {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

class Logger {
public:
    static Logger& instance();

    void set_logfile(const std::string& filepath);
    void set_level(LogLevel level);

    void log(LogLevel level, const std::string& message);

private:
    Logger() = default;
    ~Logger();

    std::ofstream logfile_;
    LogLevel current_level_ = LogLevel::Info;
    std::mutex mutex_;
};

} // namespace rgs::sdk::utils
