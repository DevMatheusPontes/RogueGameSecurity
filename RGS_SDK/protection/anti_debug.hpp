#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <optional>

namespace rgs::sdk::protection {

    enum class DebuggerType {
        Unknown,
        UserMode,
        KernelMode,
        Remote,
        Hardware
    };

    struct DebugDetection {
        DebuggerType type;
        std::string method;
        std::string description;
        bool isActive;
    };

    class AntiDebug {
    public:
        AntiDebug();
        ~AntiDebug();

        // Initialize anti-debug protection
        bool initialize();
        void shutdown();

        // Main detection methods
        std::vector<DebugDetection> scanForDebuggers();
        bool isBeingDebugged();
        
        // Specific detection methods
        bool detectPEB();
        bool detectNtGlobalFlag();
        bool detectHeapFlags();
        bool detectDebugPort();
        bool detectDebugObject();
        bool detectHardwareBreakpoints();
        bool detectSoftwareBreakpoints();
        bool detectTiming();
        bool detectExceptions();
        bool detectRemoteDebugger();
        
        // Anti-debugging techniques
        void hideFromDebugger();
        void patchDebuggerDetection();
        void enableAntiAttach();
        
        // Breakpoint detection and removal
        bool scanForBreakpoints();
        void removeBreakpoints();
        
        // Configuration
        void setProtectionEnabled(bool enabled);
        bool isProtectionEnabled() const;

    private:
        // Internal detection methods
        bool checkDebuggerPresent();
        bool checkRemoteDebuggerPresent();
        bool checkKernelDebugger();
        bool scanMemoryForBreakpoints();
        
        // Anti-debugging helpers
        void patchIsDebuggerPresent();
        void patchCheckRemoteDebuggerPresent();
        void patchNtQueryInformationProcess();
        
        // Timing checks
        bool performTimingCheck();
        DWORD measureExecutionTime();
        
        // Exception handling
        bool testExceptionHandling();
        
        bool m_protectionEnabled = true;
        bool m_initialized = false;
    };

} // namespace rgs::sdk::protection