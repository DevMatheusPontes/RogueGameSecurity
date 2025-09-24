#include "logger.hpp"
#include <iostream>

namespace rgs::sdk::utils {

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    if (logfile_.is_open()) {
        logfile_.close();
    }
}

void Logger::set_logfile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logfile_.is_open()) logfile_.close();
    logfile_.open(filepath, std::ios::out | std::ios::app);
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_level_ = level;
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < current_level_) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto now = boost::posix_time::second_clock::local_time();
    std::ostringstream oss;
    oss << "[" << boost::posix_time::to_simple_string(now) << "] ";

    switch (level) {
        case LogLevel::Debug:    oss << "[DEBUG] "; break;
        case LogLevel::Info:     oss << "[INFO] "; break;
        case LogLevel::Warning:  oss << "[WARN] "; break;
        case LogLevel::Error:    oss << "[ERROR] "; break;
        case LogLevel::Critical: oss << "[CRITICAL] "; break;
    }

    oss << message << "\n";

    // Escreve no console
    std::cout << oss.str();

    // Escreve no arquivo, se configurado
    if (logfile_.is_open()) {
        logfile_ << oss.str();
        logfile_.flush();
    }
}

} // namespace rgs::sdk::utils
