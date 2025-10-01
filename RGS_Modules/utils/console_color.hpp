#pragma once

#if defined(_WIN32)
  #include <Windows.h>
#endif

namespace rgs::utils::console {

enum class Color {
    Reset = -1,
    Green,
    Yellow,
    Red,
    Cyan,
    Gray
};

// Define a cor do console. Em ambientes não-Windows, é no-op.
void set_console_color(Color c);

// Restaura a cor padrão.
void reset_console_color();

} // namespace rgs::utils::console