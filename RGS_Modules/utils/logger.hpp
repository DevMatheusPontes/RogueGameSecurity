#pragma once

#include <string_view>
#include <iostream>
#include <mutex>

#include "security/secure_string.hpp"
#include "console_color.hpp"

namespace rgs::utils {

enum class LogLevel { Debug, Info, Warning, Error };

// Logger unificado (singleton). Cores são opcionais via parâmetro 'colorize'.
class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    // Mensagem em texto
    void log(LogLevel level, std::string_view msg, bool colorize = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (colorize) set_color(level);
        std::cout << "[" << level_to_string(level) << "] " << msg << std::endl;
        if (colorize) reset_color();
    }

    // Mensagem via SecureString
    void log(LogLevel level, rgs::security::SecureString& s, bool colorize = true) {
        s.with_decrypted_view([&](std::string_view view) {
            log(level, view, colorize);
        });
    }

private:
    std::mutex mutex_;

    Logger() = default;

    void set_color(LogLevel level) {
        using namespace rgs::utils::console;
        switch (level) {
            case LogLevel::Debug:   set_console_color(Color::Cyan);   break;
            case LogLevel::Info:    set_console_color(Color::Green);  break;
            case LogLevel::Warning: set_console_color(Color::Yellow); break;
            case LogLevel::Error:   set_console_color(Color::Red);    break;
        }
    }

    void reset_color() {
        using namespace rgs::utils::console;
        reset_console_color();
    }

    const char* level_to_string(LogLevel level) const {
        switch (level) {
            case LogLevel::Debug:   return "DEBUG";
            case LogLevel::Info:    return "INFO";
            case LogLevel::Warning: return "WARN";
            case LogLevel::Error:   return "ERROR";
        }
        return "UNKNOWN";
    }
};

} // namespace rgs::utils