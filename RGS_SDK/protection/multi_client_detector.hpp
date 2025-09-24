#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

struct MultiClientDetection {
    DWORD       pid;
    std::string exeName;
    std::string reason;
    bool        isSuspicious;
};

class MultiClientDetector {
public:
    MultiClientDetector();
    ~MultiClientDetector();

    bool initialize(const std::wstring& mutexName, const std::wstring& windowTitle);
    void shutdown();

    // Scans
    std::vector<MultiClientDetection> scan_processes();
    std::vector<MultiClientDetection> scan_windows();

    // Agregado
    bool detect_multiple_instances();

    // Últimos eventos
    std::vector<MultiClientDetection> last_events() const;

    // Resposta ativa
    void enforce_single_instance();

private:
    HANDLE mutexHandle_{nullptr};
    std::wstring mutexName_;
    std::wstring windowTitle_;

    std::atomic<bool> initialized_{false};
    std::vector<MultiClientDetection> events_;
};

} // namespace rgs::sdk::protection
