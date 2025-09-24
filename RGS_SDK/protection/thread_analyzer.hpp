#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

struct ThreadDetection {
    DWORD       tid;          // Thread ID
    uintptr_t   startAddress; // Endereço inicial
    std::string module;       // Módulo associado (se houver)
    bool        isSuspicious;
    std::string reason;
};

class ThreadAnalyzer {
public:
    ThreadAnalyzer();
    ~ThreadAnalyzer();

    bool initialize();
    void shutdown();

    // Varredura
    std::vector<ThreadDetection> scan_threads();

    // Detecção agregada
    bool detect_suspicious_threads();

    // Últimos eventos
    std::vector<ThreadDetection> last_events() const;

    // Resposta ativa
    bool suspend_thread(DWORD tid);
    bool terminate_thread(DWORD tid);

private:
    uintptr_t get_thread_start(HANDLE hThread);
    std::string module_from_address(uintptr_t addr);
    bool is_address_in_module(uintptr_t addr, std::string& modName);

private:
    std::atomic<bool> initialized_{false};
    std::vector<ThreadDetection> events_;
};

} // namespace rgs::sdk::protection
