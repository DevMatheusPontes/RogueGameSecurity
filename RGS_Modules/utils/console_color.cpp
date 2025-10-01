#include "console_color.hpp"

namespace rgs::utils::console {

#if defined(_WIN32)
static WORD to_win_color(Color c) {
    switch (c) {
        case Color::Green:  return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Yellow: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Red:    return FOREGROUND_RED | FOREGROUND_INTENSITY;
        case Color::Cyan:   return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case Color::Gray:   return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        case Color::Reset:
        default:            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

static HANDLE stdout_handle() {
    static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    return h;
}

void set_console_color(Color c) {
    if (c == Color::Reset) { reset_console_color(); return; }
    SetConsoleTextAttribute(stdout_handle(), to_win_color(c));
}

void reset_console_color() {
    SetConsoleTextAttribute(stdout_handle(),
                            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}
#else
void set_console_color(Color) {}
void reset_console_color() {}
#endif

} // namespace rgs::utils::console