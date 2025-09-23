#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <optional>
#include <memory>

namespace rgs::sdk::protection {

    enum class InjectionType {
        Unknown,
        DllInjection,
        ProcessHollowing,
        ManualMapping,
        ReflectiveDll,
        ThreadHijacking
    };

    struct InjectionResult {
        InjectionType type;
        std::string description;
        DWORD processId;
        uintptr_t suspiciousAddress;
        std::string modulePath;
    };

    class InjectionDetector {
    public:
        InjectionDetector();
        ~InjectionDetector();

        // Initialize the detector
        bool initialize();
        void shutdown();

        // Main detection methods
        std::vector<InjectionResult> scanForInjection();
        bool isProcessHollowed(DWORD processId);
        bool detectManualMapping();
        bool detectReflectiveDll();
        
        // DLL injection detection
        std::vector<InjectionResult> detectDllInjection();
        
        // Thread hijacking detection
        bool detectThreadHijacking();

        // Configuration
        void setDetectionEnabled(InjectionType type, bool enabled);
        bool isDetectionEnabled(InjectionType type) const;

    private:
        // Internal detection methods
        bool scanProcessMemory(DWORD processId);
        bool checkUnlinkedModules();
        bool validatePeHeaders();
        bool checkSuspiciousThreads();
        
        // Helper methods
        std::vector<MODULEENTRY32> getLoadedModules();
        std::vector<THREADENTRY32> getProcessThreads();
        bool isAddressInModule(uintptr_t address);
        
        // Configuration flags
        bool m_dllInjectionEnabled = true;
        bool m_processHollowingEnabled = true;
        bool m_manualMappingEnabled = true;
        bool m_reflectiveDllEnabled = true;
        bool m_threadHijackingEnabled = true;
        
        DWORD m_currentProcessId;
    };

} // namespace rgs::sdk::protection