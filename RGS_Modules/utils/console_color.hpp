#pragma once

#include <string>
#include <vector>

namespace rgs::utils {

enum class ConsoleColor {
    Default,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White
};

class Console {
public:
    static void setColor(ConsoleColor color);
    static void reset();
    static void print(ConsoleColor color, const std::string& text, bool newline = true);

    // 🔹 Impressão colorida por partes na mesma linha
    static void printInline(const std::vector<std::pair<ConsoleColor, std::string>>& parts);
};

}