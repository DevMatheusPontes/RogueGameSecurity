#include "protection_manager.hpp"
#include <iostream>
#include <chrono>

namespace rgs::sdk::protection {

ProtectionManager::ProtectionManager() = default;
ProtectionManager::~ProtectionManager() { shutdown(); }

bool ProtectionManager::initialize() {
    if (initialized_) return true;

    antiDebug_.initialize();
    antiInject_.initialize();
    antiDump_.initialize();
    antiVM_.initialize();
    antiSpeed_.initialize();
    antiHandle_.initialize();
    threadAnalyzer_.initialize();
    inputHijack_.initialize();
    windowInspector_.initialize();
    multiClient_.initialize(L"RGS_GameMutex", L"MeuJogo");
    integrity_.initialize();
    memoryProt_.initialize();
    antiHook_.initialize();
    ifaceProt_.initialize();
    eventInterceptor_.initialize();

    initialized_ = true;
    return true;
}

void ProtectionManager::shutdown() {
    stop_monitor();

    antiDebug_.shutdown();
    antiInject_.shutdown();
    antiDump_.shutdown();
    antiVM_.shutdown();
    antiSpeed_.shutdown();
    antiHandle_.shutdown();
    threadAnalyzer_.shutdown();
    inputHijack_.shutdown();
    windowInspector_.shutdown();
    multiClient_.shutdown();
    integrity_.shutdown();
    memoryProt_.shutdown();
    antiHook_.shutdown();
    ifaceProt_.shutdown();
    eventInterceptor_.shutdown();

    initialized_ = false;
    eventos_.clear();
}

void ProtectionManager::start_monitor() {
    if (running_) return;
    running_ = true;
    worker_ = std::thread(&ProtectionManager::monitor_loop, this);
}

void ProtectionManager::stop_monitor() {
    if (!running_) return;
    running_ = false;
    if (worker_.joinable()) worker_.join();
}

std::vector<ProtectionEvent> ProtectionManager::last_events() const {
    return eventos_;
}

void ProtectionManager::monitor_loop() {
    while (running_) {
        std::vector<ProtectionEvent> batch;

        // Exemplo: AntiDebug
        if (antiDebug_.detectDebugger()) {
            batch.push_back({"AntiDebug", "Debugger", "Debugger detectado", true});
        }

        // AntiInject
        if (antiInject_.detectInjectionAttempt()) {
            batch.push_back({"AntiInject", "Injection", "Tentativa de injeção detectada", true});
        }

        // AntiDump
        if (antiDump_.detectDumpAttempt()) {
            batch.push_back({"AntiDump", "Dump", "Tentativa de dump detectada", true});
        }

        // AntiVM
        if (antiVM_.isRunningInVM()) {
            batch.push_back({"AntiVM", "VM", "Execução em VM detectada", true});
        }

        // AntiSpeedHack
        if (antiSpeed_.detect_speedhack()) {
            batch.push_back({"AntiSpeedHack", "SpeedHack", "Manipulação de tempo detectada", true});
        }

        // AntiHandle
        if (antiHandle_.detect_suspicious_handles()) {
            batch.push_back({"AntiHandle", "Handle", "Handles suspeitos detectados", true});
        }

        // ThreadAnalyzer
        if (threadAnalyzer_.detect_suspicious_threads()) {
            batch.push_back({"ThreadAnalyzer", "Thread", "Threads suspeitas detectadas", true});
        }

        // InputHijack
        if (inputHijack_.detect_input_hijack()) {
            batch.push_back({"InputHijack", "Input", "Automação/hijack de input detectado", true});
        }

        // WindowInspector
        if (windowInspector_.detect_suspicious_windows()) {
            batch.push_back({"WindowInspector", "Window", "Janelas suspeitas detectadas", true});
        }

        // MultiClient
        if (multiClient_.detect_multiple_instances()) {
            batch.push_back({"MultiClient", "Instance", "Múltiplas instâncias detectadas", true});
        }

        // SelfIntegrityChecker
        if (integrity_.detect_modifications()) {
            batch.push_back({"Integrity", "Modification", "Integridade comprometida", true});
        }

        // MemoryProtection
        if (memoryProt_.detectMemoryPatches()) {
            batch.push_back({"MemoryProtection", "Patch", "Patches de memória detectados", true});
        }

        // AntiHook
        if (antiHook_.detect_hooks()) {
            batch.push_back({"AntiHook", "Hook", "Hooks detectados", true});
        }

        // InterfaceProtection
        if (ifaceProt_.detect_streamproof()) {
            batch.push_back({"InterfaceProtection", "StreamProof", "Anti-stream detectado", true});
        }

        // EventInterceptor já intercepta em tempo real, mas podemos coletar eventos
        for (auto& e : eventInterceptor_.last_events()) {
            batch.push_back({"EventInterceptor", e.api, e.descricao, e.bloqueado});
        }

        if (!batch.empty()) {
            // Armazena
            eventos_.insert(eventos_.end(), batch.begin(), batch.end());

            // Resposta: se crítico, encerrar
            for (auto& ev : batch) {
                if (ev.critico) {
                    std::cerr << "[!] Evento crítico: " << ev.modulo << " :: " << ev.descricao << "\n";
                    // ExitProcess(0); // opcional
                }
            }
        }

        Sleep(2000); // intervalo de monitoramento
    }
}

} // namespace rgs::sdk::protection
