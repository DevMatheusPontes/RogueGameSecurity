#pragma once

#include <windows.h>
#include <atomic>
#include <thread>
#include <vector>
#include <string>

#include "anti_debug.hpp"
#include "anti_inject.hpp"
#include "anti_dump.hpp"
#include "anti_vm.hpp"
#include "anti_speedhack.hpp"
#include "anti_handle.hpp"
#include "thread_analyzer.hpp"
#include "input_hijack_detector.hpp"
#include "window_inspector.hpp"
#include "multi_client_detector.hpp"
#include "self_integrity_checker.hpp"
#include "memory_protection.hpp"
#include "anti_hook.hpp"
#include "interface_protection.hpp"
#include "event_interceptor.hpp"

namespace rgs::sdk::protection {

struct ProtectionEvent {
    std::string modulo;
    std::string tipo;
    std::string descricao;
    bool critico;
};

class ProtectionManager {
public:
    ProtectionManager();
    ~ProtectionManager();

    bool initialize();
    void shutdown();

    void start_monitor();
    void stop_monitor();

    std::vector<ProtectionEvent> last_events() const;

private:
    void monitor_loop();

private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::thread worker_;

    std::vector<ProtectionEvent> eventos_;

    // Instâncias dos módulos
    AntiDebug            antiDebug_;
    AntiInject           antiInject_;
    AntiDump             antiDump_;
    AntiVM               antiVM_;
    AntiSpeedHack        antiSpeed_;
    AntiHandle           antiHandle_;
    ThreadAnalyzer       threadAnalyzer_;
    InputHijackDetector  inputHijack_;
    WindowInspector      windowInspector_;
    MultiClientDetector  multiClient_;
    SelfIntegrityChecker integrity_;
    MemoryProtection     memoryProt_;
    AntiHook             antiHook_;
    InterfaceProtection  ifaceProt_;
    EventInterceptor     eventInterceptor_;
};

} // namespace rgs::sdk::protection
