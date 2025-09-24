#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <optional>

namespace rgs::sdk::protection {

    // Tipos de debugger possíveis
    enum class DebuggerType {
        Unknown,
        UserModeAPI,
        UserModePEB,
        UserModeGlobalFlag,
        UserModeHeap,
        UserModePort,
        UserModeObject,
        UserModeCPUID,
        UserModeTiming,
        UserModeTrap,
        UserModeWindow,
        UserModeProcess,
        KernelMode,
        Hypervisor,
        Remote,
        Hardware
    };

    // Resultado de cada técnica
    struct DebugDetection {
        DebuggerType   type;
        std::string    method;
        std::string    description;
        bool           isActive;
    };

    class AntiDebug {
    public:
        AntiDebug();
        ~AntiDebug();

        // Inicializa / encerra o módulo
        bool initialize();
        void shutdown();

        // Executa todas as verificações e retorna uma lista de detecções
        std::vector<DebugDetection> scanForDebuggers();

        // Retorna true se alguma técnica detectou debugger
        bool isBeingDebugged();

        // Habilita / desabilita checagens em tempo de execução
        void setProtectionEnabled(bool enabled);
        bool isProtectionEnabled() const;

        // Técnicas de evasão / resposta
        void hideFromDebugger();
        void patchDebuggerAPIs();
        void disableDebugPrivileges();

    private:
        bool m_initialized   = false;
        bool m_enabled       = true;

        // Métodos de detecção
        bool checkIsDebuggerPresent();                        // API
        bool checkRemoteDebuggerPresent();                    // API
        bool detectPEBBeingDebugged();                        // PEB flag
        bool detectPEBNtGlobalFlag();                         // PEB NtGlobalFlag
        bool detectHeapFlags();                               // Heap flags
        bool detectDebugPort();                               // NtQueryInformationProcess DebugPort
        bool detectDebugObject();                             // NtQueryInformationProcess DebugObject
        bool detectKernelDebugger();                          // NtQuerySystemInformation
        bool detectHardwareBreakpoints();                     // Dr0–Dr3
        bool detectSoftwareBreakpoints();                     // INT3 scan
        bool detectTimingAnomaly();                           // Loop timing
        bool detectOutputDebugStringTrap();                   // OutputDebugString exception
        bool detectDebuggerWindows();                         // Janela de debuggers
        bool detectDebuggerProcesses();                       // Processo de debuggers
        bool detectHypervisor();                              // CPUID hypervisor bit
        bool detectStealthHooks();                            // IAT/EAT inline hooks, SSDT/EAT
        bool detectIDTIntegrity();                            // IDT checksum

        // Helpers de evasão
        void patchAPI(const char* module, const char* func);
        bool adjustPrivilege(const wchar_t* priv, bool enable);

        // Medição de tempo
        DWORD measureLoopTime(size_t iterations = 1000000);
    };

} // namespace rgs::sdk::protection
