#include "console_color.hpp"
#include <windows.h>
#include <iostream>

namespace rgs::utils {

namespace {
    WORD getColorAttribute(ConsoleColor color) {
        switch (color) {
            case ConsoleColor::Red:     return FOREGROUND_RED | FOREGROUND_INTENSITY;
            case ConsoleColor::Green:   return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            case ConsoleColor::Yellow:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            case ConsoleColor::Blue:    return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            case ConsoleColor::Magenta: return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            case ConsoleColor::Cyan:    return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            case ConsoleColor::White:   return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            case ConsoleColor::Default: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            default: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        }
    }

    HANDLE getConsoleHandle() {
        return GetStdHandle(STD_OUTPUT_HANDLE);
    }
}

void Console::setColor(ConsoleColor color) {
    SetConsoleTextAttribute(getConsoleHandle(), getColorAttribute(color));
}

void Console::reset() {
    setColor(ConsoleColor::Default);
}

void Console::print(ConsoleColor color, const std::string& text, bool newline) {
    setColor(color);
    if (newline)
        std::cout << text << std::endl;
    else
        std::cout << text;
    reset();
}

void Console::printInline(const std::vector<std::pair<ConsoleColor, std::string>>& parts) {
    for (const auto& [color, text] : parts) {
        setColor(color);
        std::cout << text;
    }
    reset();
    std::cout << std::endl;
}

}