#include "window_inspector.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

namespace rgs::sdk::protection {

WindowInspector::WindowInspector() = default;
WindowInspector::~WindowInspector() { shutdown(); }

bool WindowInspector::initialize() {
    initialized_ = true;
    return true;
}

void WindowInspector::shutdown() {
    initialized_ = false;
    events_.clear();
}

std::vector<WindowDetection> WindowInspector::last_events() const {
    return events_;
}

std::vector<WindowDetection> WindowInspector::scan_windows() {
    events_.clear();
    EnumWindows(enum_windows_proc, reinterpret_cast<LPARAM>(this));
    return events_;
}

bool WindowInspector::detect_suspicious_windows() {
    auto res = scan_windows();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

bool WindowInspector::close_window(HWND hwnd) {
    if (!IsWindow(hwnd)) return false;
    return PostMessage(hwnd, WM_CLOSE, 0, 0) != 0;
}

BOOL CALLBACK WindowInspector::enum_windows_proc(HWND hwnd, LPARAM lParam) {
    auto self = reinterpret_cast<WindowInspector*>(lParam);

    char cls[256]{};
    char title[256]{};
    GetClassNameA(hwnd, cls, sizeof(cls));
    GetWindowTextA(hwnd, title, sizeof(title));

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    std::string scls(cls);
    std::string stitle(title);

    // Lista de classes/títulos suspeitos
    static const std::vector<std::string> suspiciousClasses = {
        "OLLYDBG", "WinDbgFrameClass", "Qt5QWindowIcon", "Cheat Engine", "ProcessHacker"
    };
    static const std::vector<std::string> suspiciousTitles = {
        "Cheat Engine", "x64dbg", "OllyDbg", "Process Hacker", "IDA"
    };

    bool susp = false;
    std::string reason;

    for (auto& c : suspiciousClasses) {
        std::string lowCls = scls; std::transform(lowCls.begin(), lowCls.end(), lowCls.begin(), ::tolower);
        std::string lowC = c; std::transform(lowC.begin(), lowC.end(), lowC.begin(), ::tolower);
        if (lowCls.find(lowC) != std::string::npos) {
            susp = true; reason = "Classe suspeita: " + c; break;
        }
    }

    for (auto& t : suspiciousTitles) {
        std::string lowTitle = stitle; std::transform(lowTitle.begin(), lowTitle.end(), lowTitle.begin(), ::tolower);
        std::string lowT = t; std::transform(lowT.begin(), lowT.end(), lowT.begin(), ::tolower);
        if (lowTitle.find(lowT) != std::string::npos) {
            susp = true; reason = "Título suspeito: " + t; break;
        }
    }

    // Janelas invisíveis mas com título/classe suspeita
    if (!IsWindowVisible(hwnd) && susp) {
        reason += " (janela oculta)";
    }

    WindowDetection det;
    det.hwnd        = hwnd;
    det.pid         = pid;
    det.className   = scls;
    det.title       = stitle;
    det.isSuspicious= susp;
    det.reason      = susp ? reason : "Janela legítima";

    self->events_.push_back(det);
    return TRUE;
}

} // namespace rgs::sdk::protection
