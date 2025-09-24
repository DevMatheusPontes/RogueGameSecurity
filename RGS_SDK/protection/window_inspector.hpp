#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

struct WindowDetection {
    HWND        hwnd;
    DWORD       pid;
    std::string className;
    std::string title;
    bool        isSuspicious;
    std::string reason;
};

class WindowInspector {
public:
    WindowInspector();
    ~WindowInspector();

    bool initialize();
    void shutdown();

    // Varredura
    std::vector<WindowDetection> scan_windows();

    // Detecção agregada
    bool detect_suspicious_windows();

    // Últimos eventos
    std::vector<WindowDetection> last_events() const;

    // Resposta ativa
    bool close_window(HWND hwnd);

private:
    static BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM lParam);

private:
    std::atomic<bool> initialized_{false};
    std::vector<WindowDetection> events_;
};

} // namespace rgs::sdk::protection
