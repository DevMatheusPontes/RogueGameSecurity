#include "injection_detector.hpp"
#include "../memory/memory_access.hpp"
#include <psapi.h>
#include <iostream>
#include <algorithm>

namespace rgs::sdk::protection {

    InjectionDetector::InjectionDetector() {
        m_currentProcessId = GetCurrentProcessId();
    }

    InjectionDetector::~InjectionDetector() {
        shutdown();
    }

    bool InjectionDetector::initialize() {
        return true;
    }

    void InjectionDetector::shutdown() {
        // Cleanup any resources
    }

    std::vector<InjectionResult> InjectionDetector::scanForInjection() {
        std::vector<InjectionResult> results;
        
        if (m_dllInjectionEnabled) {
            auto dllResults = detectDllInjection();
            results.insert(results.end(), dllResults.begin(), dllResults.end());
        }

        if (m_processHollowingEnabled && isProcessHollowed(m_currentProcessId)) {
            InjectionResult result;
            result.type = InjectionType::ProcessHollowing;
            result.description = "Process hollowing detected";
            result.processId = m_currentProcessId;
            result.suspiciousAddress = 0;
            results.push_back(result);
        }

        if (m_manualMappingEnabled && detectManualMapping()) {
            InjectionResult result;
            result.type = InjectionType::ManualMapping;
            result.description = "Manual mapping detected";
            result.processId = m_currentProcessId;
            result.suspiciousAddress = 0;
            results.push_back(result);
        }

        if (m_reflectiveDllEnabled && detectReflectiveDll()) {
            InjectionResult result;
            result.type = InjectionType::ReflectiveDll;
            result.description = "Reflective DLL detected";
            result.processId = m_currentProcessId;
            result.suspiciousAddress = 0;
            results.push_back(result);
        }

        if (m_threadHijackingEnabled && detectThreadHijacking()) {
            InjectionResult result;
            result.type = InjectionType::ThreadHijacking;
            result.description = "Thread hijacking detected";
            result.processId = m_currentProcessId;
            result.suspiciousAddress = 0;
            results.push_back(result);
        }

        return results;
    }

    bool InjectionDetector::isProcessHollowed(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool isHollowed = false;
        
        // Get process base address
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            // Read DOS header
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, hMod, &dosHeader, sizeof(dosHeader), &bytesRead)) {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    // Read NT header
                    IMAGE_NT_HEADERS ntHeaders;
                    LPBYTE ntHeadersAddr = (LPBYTE)hMod + dosHeader.e_lfanew;
                    if (ReadProcessMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
                        if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                            // Check entry point
                            DWORD entryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
                            LPBYTE entryAddr = (LPBYTE)hMod + entryPoint;
                            
                            // Read entry point code
                            BYTE entryCode[16];
                            if (ReadProcessMemory(hProcess, entryAddr, entryCode, sizeof(entryCode), &bytesRead)) {
                                // Check for suspicious patterns (nops, jumps to unexpected locations)
                                for (int i = 0; i < 8; i++) {
                                    if (entryCode[i] == 0x90) { // NOP instruction
                                        isHollowed = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        CloseHandle(hProcess);
        return isHollowed;
    }

    bool InjectionDetector::detectManualMapping() {
        auto modules = getLoadedModules();
        MEMORY_BASIC_INFORMATION mbi;
        
        // Scan virtual memory for unmapped modules
        for (uintptr_t addr = 0x10000; addr < 0x7FFFFFFF; addr += mbi.RegionSize) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
                continue;
            }
            
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                // Check if this looks like a PE header
                auto peHeader = rgs::sdk::memory::read<IMAGE_DOS_HEADER>(addr);
                if (peHeader && peHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                    // Check if this address is in any loaded module
                    if (!isAddressInModule(addr)) {
                        return true; // Found manually mapped module
                    }
                }
            }
        }
        
        return false;
    }

    bool InjectionDetector::detectReflectiveDll() {
        // Check for reflective DLL patterns in executable memory regions
        MEMORY_BASIC_INFORMATION mbi;
        
        for (uintptr_t addr = 0x10000; addr < 0x7FFFFFFF; addr += mbi.RegionSize) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
                continue;
            }
            
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                // Read first few bytes to check for reflective DLL signature
                auto buffer = rgs::sdk::memory::readBuffer(addr, 64);
                if (!buffer.empty()) {
                    // Look for common reflective DLL patterns
                    std::vector<std::byte> pattern = {
                        std::byte{0x4C}, std::byte{0x8B}, std::byte{0xDC},  // mov r11, rsp
                        std::byte{0x49}, std::byte{0x89}, std::byte{0x5B}   // mov [r11+8], rbx
                    };
                    
                    for (size_t i = 0; i <= buffer.size() - pattern.size(); i++) {
                        bool found = true;
                        for (size_t j = 0; j < pattern.size(); j++) {
                            if (buffer[i + j] != pattern[j]) {
                                found = false;
                                break;
                            }
                        }
                        if (found) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }

    std::vector<InjectionResult> InjectionDetector::detectDllInjection() {
        std::vector<InjectionResult> results;
        auto modules = getLoadedModules();
        
        for (const auto& module : modules) {
            // Check if module is in suspicious location
            std::string modulePath = module.szExePath;
            std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::tolower);
            
            // Check for common injection indicators
            if (modulePath.find("temp") != std::string::npos ||
                modulePath.find("appdata") != std::string::npos ||
                modulePath.empty()) {
                
                InjectionResult result;
                result.type = InjectionType::DllInjection;
                result.description = "Suspicious DLL loaded: " + std::string(module.szModule);
                result.processId = m_currentProcessId;
                result.suspiciousAddress = reinterpret_cast<uintptr_t>(module.modBaseAddr);
                result.modulePath = module.szExePath;
                results.push_back(result);
            }
        }
        
        return results;
    }

    bool InjectionDetector::detectThreadHijacking() {
        auto threads = getProcessThreads();
        
        for (const auto& thread : threads) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, thread.th32ThreadID);
            if (hThread) {
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(hThread, &ctx)) {
                    // Check if thread is executing in suspicious memory region
#ifdef _WIN64
                    if (!isAddressInModule(ctx.Rip)) {
#else
                    if (!isAddressInModule(ctx.Eip)) {
#endif
                        CloseHandle(hThread);
                        return true;
                    }
                }
                CloseHandle(hThread);
            }
        }
        
        return false;
    }

    std::vector<MODULEENTRY32> InjectionDetector::getLoadedModules() {
        std::vector<MODULEENTRY32> modules;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_currentProcessId);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            
            if (Module32First(hSnapshot, &me32)) {
                do {
                    modules.push_back(me32);
                } while (Module32Next(hSnapshot, &me32));
            }
            CloseHandle(hSnapshot);
        }
        
        return modules;
    }

    std::vector<THREADENTRY32> InjectionDetector::getProcessThreads() {
        std::vector<THREADENTRY32> threads;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            
            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == m_currentProcessId) {
                        threads.push_back(te32);
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
        
        return threads;
    }

    bool InjectionDetector::isAddressInModule(uintptr_t address) {
        auto modules = getLoadedModules();
        
        for (const auto& module : modules) {
            uintptr_t baseAddr = reinterpret_cast<uintptr_t>(module.modBaseAddr);
            if (address >= baseAddr && address < baseAddr + module.modBaseSize) {
                return true;
            }
        }
        
        return false;
    }

    void InjectionDetector::setDetectionEnabled(InjectionType type, bool enabled) {
        switch (type) {
            case InjectionType::DllInjection:
                m_dllInjectionEnabled = enabled;
                break;
            case InjectionType::ProcessHollowing:
                m_processHollowingEnabled = enabled;
                break;
            case InjectionType::ManualMapping:
                m_manualMappingEnabled = enabled;
                break;
            case InjectionType::ReflectiveDll:
                m_reflectiveDllEnabled = enabled;
                break;
            case InjectionType::ThreadHijacking:
                m_threadHijackingEnabled = enabled;
                break;
        }
    }

    bool InjectionDetector::isDetectionEnabled(InjectionType type) const {
        switch (type) {
            case InjectionType::DllInjection:
                return m_dllInjectionEnabled;
            case InjectionType::ProcessHollowing:
                return m_processHollowingEnabled;
            case InjectionType::ManualMapping:
                return m_manualMappingEnabled;
            case InjectionType::ReflectiveDll:
                return m_reflectiveDllEnabled;
            case InjectionType::ThreadHijacking:
                return m_threadHijackingEnabled;
            default:
                return false;
        }
    }

} // namespace rgs::sdk::protection