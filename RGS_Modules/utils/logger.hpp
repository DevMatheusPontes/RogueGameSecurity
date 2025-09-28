#pragma once

#include "console_color.hpp"
#include <string>

namespace rgs::utils {

enum class LogLevel { Info, Warning, Error, Debug };

class Logger {
public:
    static void log(LogLevel level, const std::string& msg);
};

}