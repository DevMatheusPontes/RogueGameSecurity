#include "input_hijack_detector.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <chrono>
#include <thread>

namespace rgs::sdk::protection {

InputHijackDetector::InputHijackDetector() = default;
InputHijackDetector::~InputHijackDetector() { shutdown(); }

bool InputHijackDetector::initialize() {
    initialized_ = true;
    return true;
}

void InputHijackDetector::shutdown() {
    initialized_ = false;
    events_.clear();
}

std::vector<InputDetection> InputHijackDetector::last_events() const {
    return events_;
}

std::vector<InputDetection> InputHijackDetector::scan_hooks() {
    std::vector<InputDetection> out;
    InputDetection det{};
    if (check_hooks(det)) out.push_back(det);
    events_.insert(events_.end(), out.begin(), out.end());
    return out;
}

std::vector<InputDetection> InputHijackDetector::scan_automation() {
    std::vector<InputDetection> out;
    InputDetection det{};
    if (check_sendinput_pattern(det)) out.push_back(det);
    events_.insert(events_.end(), out.begin(), out.end());
    return out;
}

std::vector<InputDetection> InputHijackDetector::scan_windows() {
    std::vector<InputDetection> out;
    InputDetection det{};
    if (check_hidden_windows(det)) out.push_back(det);
    events_.insert(events_.end(), out.begin(), out.end());
    return out;
}

bool InputHijackDetector::detect_input_hijack() {
    auto h = scan_hooks();
    auto a = scan_automation();
    auto w = scan_windows();
    auto any = [](const std::vector<InputDetection>& v){
        return std::any_of(v.begin(), v.end(), [](auto& d){ return d.isSuspicious; });
    };
    return any(h) || any(a) || any(w);
}

// ——————————————————————————— Checks ———————————————————————————

bool InputHijackDetector::check_hooks(InputDetection& out) {
    // Heurística: verifica se há hooks globais de teclado/mouse
    HHOOK kbd = GetWindowsHookEx(WH_KEYBOARD_LL, nullptr, nullptr, 0);
    HHOOK mse = GetWindowsHookEx(WH_MOUSE_LL, nullptr, nullptr, 0);
    if (kbd || mse) {
        out = { "Hooks", "Hook global de teclado/mouse detectado", GetCurrentThreadId(), true };
        if (kbd) UnhookWindowsHookEx(kbd);
        if (mse) UnhookWindowsHookEx(mse);
        return true;
    }
    return false;
}

bool InputHijackDetector::check_sendinput_pattern(InputDetection& out) {
    // Heurística: detectar automação por padrões de input constantes
    // Aqui simulamos: se em curto intervalo houver muitos eventos idênticos, suspeito.
    static int counter = 0;
    counter++;
    if (counter > 100) {
        out = { "SendInput", "Padrão de automação detectado (inputs constantes)", GetCurrentThreadId(), true };
        counter = 0;
        return true;
    }
    return false;
}

bool InputHijackDetector::check_hidden_windows(InputDetection& out) {
    HWND hwnd = FindWindowA("AutoClickerClass", nullptr);
    if (hwnd) {
        out = { "HiddenWindow", "Janela suspeita de automação detectada", GetCurrentThreadId(), true };
        return true;
    }
    return false;
}

// ——————————————————————————— Resposta ativa ———————————————————————————

bool InputHijackDetector::unhook_thread(DWORD tid) {
    // Melhor esforço: suspender thread suspeita
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) return false;
    SuspendThread(th);
    CloseHandle(th);
    return true;
}

} // namespace rgs::sdk::protection
