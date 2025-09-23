#include "anti_debug.hpp"
#include "../hooks/hook_manager.hpp"
#include "../memory/memory_access.hpp"
#include <winternl.h>

// NT API definitions
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace rgs::sdk::protection {

    AntiDebug::AntiDebug() {
        
    }

    AntiDebug::~AntiDebug() {
        shutdown();
    }

    bool AntiDebug::initialize() {
        if (m_initialized) {
            return true;
        }

        // Initialize hook manager if needed
        auto& hookManager = rgs::sdk::hooks::HookManager::getInstance();
        if (!hookManager.initialize()) {
            return false;
        }

        // Apply anti-debugging patches
        if (m_protectionEnabled) {
            patchDebuggerDetection();
            enableAntiAttach();
        }

        m_initialized = true;
        return true;
    }

    void AntiDebug::shutdown() {
        if (!m_initialized) {
            return;
        }

        // Remove any hooks we installed
        auto& hookManager = rgs::sdk::hooks::HookManager::getInstance();
        hookManager.removeHook("IsDebuggerPresent");
        hookManager.removeHook("CheckRemoteDebuggerPresent");
        hookManager.removeHook("NtQueryInformationProcess");

        m_initialized = false;
    }

    std::vector<DebugDetection> AntiDebug::scanForDebuggers() {
        std::vector<DebugDetection> detections;

        // PEB-based detection
        if (detectPEB()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "PEB.BeingDebugged";
            det.description = "Debugger detected via PEB BeingDebugged flag";
            det.isActive = true;
            detections.push_back(det);
        }

        // NT Global Flag detection
        if (detectNtGlobalFlag()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "PEB.NtGlobalFlag";
            det.description = "Debugger detected via NT Global Flag";
            det.isActive = true;
            detections.push_back(det);
        }

        // Heap flags detection
        if (detectHeapFlags()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "HeapFlags";
            det.description = "Debugger detected via heap flags";
            det.isActive = true;
            detections.push_back(det);
        }

        // Debug port detection
        if (detectDebugPort()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "DebugPort";
            det.description = "Debugger detected via debug port";
            det.isActive = true;
            detections.push_back(det);
        }

        // Hardware breakpoint detection
        if (detectHardwareBreakpoints()) {
            DebugDetection det;
            det.type = DebuggerType::Hardware;
            det.method = "HardwareBreakpoints";
            det.description = "Hardware breakpoints detected";
            det.isActive = true;
            detections.push_back(det);
        }

        // Software breakpoint detection
        if (detectSoftwareBreakpoints()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "SoftwareBreakpoints";
            det.description = "Software breakpoints detected";
            det.isActive = true;
            detections.push_back(det);
        }

        // Timing-based detection
        if (detectTiming()) {
            DebugDetection det;
            det.type = DebuggerType::UserMode;
            det.method = "TimingCheck";
            det.description = "Debugger detected via timing analysis";
            det.isActive = true;
            detections.push_back(det);
        }

        // Remote debugger detection
        if (detectRemoteDebugger()) {
            DebugDetection det;
            det.type = DebuggerType::Remote;
            det.method = "RemoteDebugger";
            det.description = "Remote debugger detected";
            det.isActive = true;
            detections.push_back(det);
        }

        return detections;
    }

    bool AntiDebug::isBeingDebugged() {
        return detectPEB() || detectDebugPort() || detectHardwareBreakpoints() || 
               detectSoftwareBreakpoints() || detectTiming();
    }

    bool AntiDebug::detectPEB() {
        // Check PEB BeingDebugged flag
        __try {
#ifdef _WIN64
            PPEB peb = (PPEB)__readgsqword(0x60);
#else
            PPEB peb = (PPEB)__readfsdword(0x30);
#endif
            return peb->BeingDebugged != 0;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::detectNtGlobalFlag() {
        __try {
#ifdef _WIN64
            PPEB peb = (PPEB)__readgsqword(0x60);
#else
            PPEB peb = (PPEB)__readfsdword(0x30);
#endif
            // Check NT Global Flag for debug heap flags
            return (peb->NtGlobalFlag & 0x70) != 0;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::detectHeapFlags() {
        __try {
#ifdef _WIN64
            PPEB peb = (PPEB)__readgsqword(0x60);
#else
            PPEB peb = (PPEB)__readfsdword(0x30);
#endif
            PVOID heap = peb->ProcessHeap;
            if (!heap) return false;

            // Check heap flags
            DWORD flags = *((DWORD*)((BYTE*)heap + 0x40));
            DWORD forceFlags = *((DWORD*)((BYTE*)heap + 0x44));
            
            return (flags & ~HEAP_GROWABLE) || (forceFlags != 0);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::detectDebugPort() {
        HANDLE hProcess = GetCurrentProcess();
        DWORD debugPort = 0;
        ULONG returnLength = 0;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!NtQueryInformationProcess) return false;

        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            &returnLength
        );

        return (NT_SUCCESS(status) && debugPort != 0);
    }

    bool AntiDebug::detectDebugObject() {
        HANDLE hProcess = GetCurrentProcess();
        HANDLE debugObject = NULL;
        ULONG returnLength = 0;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!NtQueryInformationProcess) return false;

        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            ProcessDebugObjectHandle,
            &debugObject,
            sizeof(debugObject),
            &returnLength
        );

        return (NT_SUCCESS(status) && debugObject != NULL);
    }

    bool AntiDebug::detectHardwareBreakpoints() {
        CONTEXT ctx;
        HANDLE hThread = GetCurrentThread();

        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(hThread, &ctx)) {
            return false;
        }

        // Check if any debug registers are set
        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr7 != 0);
    }

    bool AntiDebug::detectSoftwareBreakpoints() {
        return scanMemoryForBreakpoints();
    }

    bool AntiDebug::detectTiming() {
        LARGE_INTEGER start, end, frequency;
        
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        
        // Perform some simple operations
        for (int i = 0; i < 100; i++) {
            __nop();
        }
        
        QueryPerformanceCounter(&end);
        
        // Calculate execution time in microseconds
        double timeElapsed = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / frequency.QuadPart;
        
        // If execution took too long, likely being debugged
        return timeElapsed > 1000.0; // 1ms threshold
    }

    bool AntiDebug::detectExceptions() {
        __try {
            // Trigger an exception and check if it's handled properly
            *(int*)0 = 0;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false; // Exception handled normally
        }
        return true; // Should not reach here if debugger isn't present
    }

    bool AntiDebug::detectRemoteDebugger() {
        BOOL isRemoteDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent)) {
            return isRemoteDebuggerPresent != FALSE;
        }
        return false;
    }

    void AntiDebug::hideFromDebugger() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return;

        typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
            HANDLE ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID ThreadInformation,
            ULONG ThreadInformationLength
        );

        pNtSetInformationThread NtSetInformationThread = 
            (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
        }
    }

    void AntiDebug::patchDebuggerDetection() {
        patchIsDebuggerPresent();
        patchCheckRemoteDebuggerPresent();
        patchNtQueryInformationProcess();
    }

    void AntiDebug::enableAntiAttach() {
        hideFromDebugger();
    }

    bool AntiDebug::scanForBreakpoints() {
        return scanMemoryForBreakpoints();
    }

    void AntiDebug::removeBreakpoints() {
        // Scan for and remove software breakpoints (0xCC, 0xCD03)
        MEMORY_BASIC_INFORMATION mbi;
        for (uintptr_t addr = 0x400000; addr < 0x7FFFFFFF; addr += mbi.RegionSize) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
                continue;
            }

            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {
                auto buffer = rgs::sdk::memory::readBuffer(addr, mbi.RegionSize);
                for (size_t i = 0; i < buffer.size(); i++) {
                    if (buffer[i] == std::byte{0xCC}) { // INT3 breakpoint
                        // Replace with original instruction (would need to be stored)
                        rgs::sdk::memory::write<BYTE>(addr + i, 0x90); // NOP for now
                    }
                }
            }
        }
    }

    bool AntiDebug::scanMemoryForBreakpoints() {
        MEMORY_BASIC_INFORMATION mbi;
        for (uintptr_t addr = 0x400000; addr < 0x7FFFFFFF; addr += mbi.RegionSize) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
                continue;
            }

            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {
                auto buffer = rgs::sdk::memory::readBuffer(addr, mbi.RegionSize);
                for (const auto& byte : buffer) {
                    if (byte == std::byte{0xCC} || byte == std::byte{0xCD}) {
                        return true; // Breakpoint found
                    }
                }
            }
        }
        return false;
    }

    void AntiDebug::patchIsDebuggerPresent() {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return;

        FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
        if (!pIsDebuggerPresent) return;

        // Hook IsDebuggerPresent to always return FALSE
        auto& hookManager = rgs::sdk::hooks::HookManager::getInstance();
        
        auto fakeIsDebuggerPresent = []() -> BOOL {
            return FALSE;
        };

        hookManager.installHook("IsDebuggerPresent", pIsDebuggerPresent, 
                               reinterpret_cast<void*>(fakeIsDebuggerPresent));
        hookManager.enableHook("IsDebuggerPresent");
    }

    void AntiDebug::patchCheckRemoteDebuggerPresent() {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return;

        FARPROC pCheckRemoteDebuggerPresent = GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");
        if (!pCheckRemoteDebuggerPresent) return;

        auto& hookManager = rgs::sdk::hooks::HookManager::getInstance();
        
        auto fakeCheckRemoteDebuggerPresent = [](HANDLE hProcess, PBOOL pbDebuggerPresent) -> BOOL {
            if (pbDebuggerPresent) {
                *pbDebuggerPresent = FALSE;
            }
            return TRUE;
        };

        hookManager.installHook("CheckRemoteDebuggerPresent", pCheckRemoteDebuggerPresent, 
                               reinterpret_cast<void*>(fakeCheckRemoteDebuggerPresent));
        hookManager.enableHook("CheckRemoteDebuggerPresent");
    }

    void AntiDebug::patchNtQueryInformationProcess() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return;

        FARPROC pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtQueryInformationProcess) return;

        auto& hookManager = rgs::sdk::hooks::HookManager::getInstance();
        
        auto fakeNtQueryInformationProcess = [](
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength) -> NTSTATUS {
            
            if (ProcessInformationClass == ProcessDebugPort ||
                ProcessInformationClass == ProcessDebugObjectHandle) {
                return STATUS_ACCESS_DENIED;
            }
            
            // Call original function for other cases
            auto originalFunc = hookManager.getOriginal<pNtQueryInformationProcess>("NtQueryInformationProcess");
            if (originalFunc) {
                return originalFunc(ProcessHandle, ProcessInformationClass, 
                                  ProcessInformation, ProcessInformationLength, ReturnLength);
            }
            return STATUS_UNSUCCESSFUL;
        };

        hookManager.installHook("NtQueryInformationProcess", pNtQueryInformationProcess, 
                               reinterpret_cast<void*>(fakeNtQueryInformationProcess));
        hookManager.enableHook("NtQueryInformationProcess");
    }

    void AntiDebug::setProtectionEnabled(bool enabled) {
        m_protectionEnabled = enabled;
    }

    bool AntiDebug::isProtectionEnabled() const {
        return m_protectionEnabled;
    }

} // namespace rgs::sdk::protection