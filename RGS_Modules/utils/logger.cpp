#include "logger.hpp"
#include <iostream>

namespace rgs::utils {

void Logger::log(LogLevel level, const std::string& msg) {
    switch (level) {
        case LogLevel::Info:
            Console::print(ConsoleColor::Green, "[INFO] " + msg);
            break;
        case LogLevel::Warning:
            Console::print(ConsoleColor::Yellow, "[WARN] " + msg);
            break;
        case LogLevel::Error:
            Console::print(ConsoleColor::Red, "[ERROR] " + msg);
            break;
        case LogLevel::Debug:
            Console::print(ConsoleColor::Cyan, "[DEBUG] " + msg);
            break;
    }
}

}