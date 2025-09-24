#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <thread>

namespace rgs::sdk::protection {

struct IntegritySection {
    std::string name;
    uintptr_t   base;
    size_t      size;
    std::string hash; // SHA-256
};

struct IntegrityDetection {
    std::string section;
    std::string description;
    bool        isModified;
};

class SelfIntegrityChecker {
public:
    SelfIntegrityChecker();
    ~SelfIntegrityChecker();

    bool initialize();
    void shutdown();

    // Scans
    std::vector<IntegrityDetection> scan_sections();

    // Agregado
    bool detect_modifications();

    // Últimos eventos
    std::vector<IntegrityDetection> last_events() const;

    // Configuração
    void set_enable_monitor(bool enable);
    void set_poll_interval_ms(DWORD ms);

    // Execução
    bool start_monitor();
    void stop_monitor();

private:
    std::string hash_memory(uintptr_t base, size_t size);
    std::vector<IntegritySection> collect_sections();

    void monitor_loop();

private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> monitor_enabled_{true};
    std::atomic<bool> monitor_running_{false};

    DWORD poll_interval_ms_{2000};
    std::thread monitor_thread_;

    std::vector<IntegritySection> baseline_;
    std::vector<IntegrityDetection> events_;
};

} // namespace rgs::sdk::protection
