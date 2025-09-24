#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

struct InputDetection {
    std::string method;
    std::string description;
    DWORD       threadId;
    bool        isSuspicious;
};

class InputHijackDetector {
public:
    InputHijackDetector();
    ~InputHijackDetector();

    bool initialize();
    void shutdown();

    // Scans
    std::vector<InputDetection> scan_hooks();
    std::vector<InputDetection> scan_automation();
    std::vector<InputDetection> scan_windows();

    // Detecção agregada
    bool detect_input_hijack();

    // Últimos eventos
    std::vector<InputDetection> last_events() const;

    // Resposta ativa
    bool unhook_thread(DWORD tid);

private:
    bool check_hooks(InputDetection& out);
    bool check_sendinput_pattern(InputDetection& out);
    bool check_hidden_windows(InputDetection& out);

private:
    std::atomic<bool> initialized_{false};
    std::vector<InputDetection> events_;
};

} // namespace rgs::sdk::protection
