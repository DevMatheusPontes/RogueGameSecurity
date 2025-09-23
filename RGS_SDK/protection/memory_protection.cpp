#include "memory_protection.hpp"
#include "../memory/memory_access.hpp"
#include "../security/hash.hpp"
#include <psapi.h>
#include <imagehlp.h>
#include <algorithm>

#pragma comment(lib, "imagehlp.lib")

namespace rgs::sdk::protection {

    // Static instance for exception handler
    static MemoryProtection* g_instance = nullptr;

    MemoryProtection::MemoryProtection() {
        g_instance = this;
    }

    MemoryProtection::~MemoryProtection() {
        shutdown();
        g_instance = nullptr;
    }

    bool MemoryProtection::initialize() {
        if (m_initialized) {
            return true;
        }

        // Store original PE sections for comparison
        HMODULE hModule = GetModuleHandle(NULL);
        if (hModule) {
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

            for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    uintptr_t sectionAddr = (uintptr_t)hModule + sectionHeader[i].VirtualAddress;
                    size_t sectionSize = sectionHeader[i].Misc.VirtualSize;
                    
                    auto sectionData = rgs::sdk::memory::readBuffer(sectionAddr, sectionSize);
                    m_originalSections.emplace_back(sectionAddr, sectionData);
                }
            }
        }

        m_initialized = true;
        return true;
    }

    void MemoryProtection::shutdown() {
        if (!m_initialized) {
            return;
        }

        disableAntiDump();
        disableAccessMonitoring();
        
        // Clear protected regions
        m_protectedRegions.clear();
        m_detectedThreats.clear();
        m_originalSections.clear();

        m_initialized = false;
    }

    bool MemoryProtection::enableAntiDump() {
        if (m_antiDumpEnabled) {
            return true;
        }

        bool success = true;
        success &= hidePEHeader();
        success &= scrambleHeaders();
        success &= protectCriticalSections();

        m_antiDumpEnabled = success;
        return success;
    }

    void MemoryProtection::disableAntiDump() {
        if (!m_antiDumpEnabled) {
            return;
        }

        // Restore original headers if needed
        // This is complex and might not be fully reversible
        m_antiDumpEnabled = false;
    }

    bool MemoryProtection::isAntiDumpEnabled() const {
        return m_antiDumpEnabled;
    }

    bool MemoryProtection::addIntegrityRegion(uintptr_t address, size_t size, const std::string& name) {
        if (m_protectedRegions.find(name) != m_protectedRegions.end()) {
            return false; // Region already exists
        }

        MemoryIntegrityRegion region;
        region.startAddress = address;
        region.size = size;
        region.originalHash = calculateRegionHash(address, size);
        region.name = name;
        region.isProtected = true;

        // Get current protection
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            region.originalProtection = mbi.Protect;
        }

        m_protectedRegions[name] = region;
        return true;
    }

    bool MemoryProtection::removeIntegrityRegion(const std::string& name) {
        auto it = m_protectedRegions.find(name);
        if (it == m_protectedRegions.end()) {
            return false;
        }

        m_protectedRegions.erase(it);
        return true;
    }

    bool MemoryProtection::verifyIntegrity() {
        for (auto& [name, region] : m_protectedRegions) {
            if (isRegionModified(region)) {
                MemoryThreatDetection threat;
                threat.type = MemoryThreat::IntegrityViolation;
                threat.address = region.startAddress;
                threat.size = region.size;
                threat.description = "Integrity violation detected in region: " + name;
                m_detectedThreats.push_back(threat);
                return false;
            }
        }
        return true;
    }

    std::vector<MemoryThreatDetection> MemoryProtection::checkIntegrityViolations() {
        std::vector<MemoryThreatDetection> violations;

        for (const auto& [name, region] : m_protectedRegions) {
            if (isRegionModified(region)) {
                MemoryThreatDetection threat;
                threat.type = MemoryThreat::IntegrityViolation;
                threat.address = region.startAddress;
                threat.size = region.size;
                threat.description = "Integrity violation in region: " + name;
                violations.push_back(threat);
            }
        }

        return violations;
    }

    bool MemoryProtection::scanForHooks() {
        auto hooks = detectHooks();
        return !hooks.empty();
    }

    std::vector<MemoryThreatDetection> MemoryProtection::detectHooks() {
        std::vector<MemoryThreatDetection> hooks;

        // Check import table hooks
        if (checkImportTable()) {
            MemoryThreatDetection threat;
            threat.type = MemoryThreat::HookInjection;
            threat.address = 0;
            threat.size = 0;
            threat.description = "Import table hook detected";
            hooks.push_back(threat);
        }

        // Check inline hooks in critical functions
        std::vector<std::string> criticalFunctions = {
            "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
            "SetWindowsHookEx", "GetProcAddress", "LoadLibrary"
        };

        for (const auto& funcName : criticalFunctions) {
            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
            if (hKernel32) {
                FARPROC funcAddr = GetProcAddress(hKernel32, funcName.c_str());
                if (funcAddr && isAddressHooked(reinterpret_cast<uintptr_t>(funcAddr))) {
                    MemoryThreatDetection threat;
                    threat.type = MemoryThreat::HookInjection;
                    threat.address = reinterpret_cast<uintptr_t>(funcAddr);
                    threat.size = 16; // Check first 16 bytes
                    threat.description = "Inline hook detected on " + funcName;
                    hooks.push_back(threat);
                }
            }
        }

        return hooks;
    }

    bool MemoryProtection::removeDetectedHooks() {
        // This is complex and dangerous - removing hooks might crash the process
        // For now, just detect and log
        return false;
    }

    bool MemoryProtection::enableAccessMonitoring() {
        if (m_accessMonitoringEnabled) {
            return true;
        }

        // Install vectored exception handler
        m_vehHandler = AddVectoredExceptionHandler(1, vectoredExceptionHandler);
        if (!m_vehHandler) {
            return false;
        }

        // Setup page guards on critical regions
        bool success = setupPageGuards();
        if (!success) {
            RemoveVectoredExceptionHandler(m_vehHandler);
            m_vehHandler = nullptr;
            return false;
        }

        m_accessMonitoringEnabled = true;
        return true;
    }

    void MemoryProtection::disableAccessMonitoring() {
        if (!m_accessMonitoringEnabled) {
            return;
        }

        removePageGuards();

        if (m_vehHandler) {
            RemoveVectoredExceptionHandler(m_vehHandler);
            m_vehHandler = nullptr;
        }

        m_accessMonitoringEnabled = false;
    }

    std::vector<MemoryThreatDetection> MemoryProtection::getAccessViolations() {
        // Return detected access violations
        std::vector<MemoryThreatDetection> violations;
        
        for (const auto& threat : m_detectedThreats) {
            if (threat.type == MemoryThreat::IllegalAccess) {
                violations.push_back(threat);
            }
        }
        
        return violations;
    }

    bool MemoryProtection::detectCodeInjection() {
        auto injections = scanForInjectedCode();
        return !injections.empty();
    }

    std::vector<MemoryThreatDetection> MemoryProtection::scanForInjectedCode() {
        std::vector<MemoryThreatDetection> injections;

        // Scan for executable regions that shouldn't be there
        MEMORY_BASIC_INFORMATION mbi;
        for (uintptr_t addr = 0x10000; addr < 0x7FFFFFFF; addr += mbi.RegionSize) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
                continue;
            }

            // Look for executable private memory
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE_READWRITE) &&
                mbi.Type == MEM_PRIVATE) {
                
                // Check if this looks like injected code
                if (!validateExecutableCode(addr, mbi.RegionSize)) {
                    MemoryThreatDetection threat;
                    threat.type = MemoryThreat::CodeInjection;
                    threat.address = addr;
                    threat.size = mbi.RegionSize;
                    threat.description = "Suspicious executable region detected";
                    injections.push_back(threat);
                }
            }
        }

        return injections;
    }

    bool MemoryProtection::detectMemoryPatches() {
        auto patches = scanForPatches();
        return !patches.empty();
    }

    std::vector<MemoryThreatDetection> MemoryProtection::scanForPatches() {
        std::vector<MemoryThreatDetection> patches;

        // Compare current sections with original
        for (const auto& [originalAddr, originalData] : m_originalSections) {
            auto currentData = rgs::sdk::memory::readBuffer(originalAddr, originalData.size());
            
            if (currentData.size() != originalData.size()) {
                continue;
            }

            // Find differences
            for (size_t i = 0; i < originalData.size(); i++) {
                if (originalData[i] != currentData[i]) {
                    MemoryThreatDetection threat;
                    threat.type = MemoryThreat::MemoryPatch;
                    threat.address = originalAddr + i;
                    threat.size = 1;
                    threat.description = "Memory patch detected";
                    threat.suspiciousData = {currentData[i]};
                    patches.push_back(threat);
                    
                    // Skip ahead to avoid too many detections for the same patch
                    i += 15;
                }
            }
        }

        return patches;
    }

    void MemoryProtection::setProtectionLevel(int level) {
        if (level >= 1 && level <= 5) {
            m_protectionLevel = level;
        }
    }

    int MemoryProtection::getProtectionLevel() const {
        return m_protectionLevel;
    }

    void MemoryProtection::setStealthMode(bool enabled) {
        m_stealthMode = enabled;
    }

    // Private helper methods

    bool MemoryProtection::hidePEHeader() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        
        // Scramble DOS header
        DWORD oldProtect;
        if (VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &oldProtect)) {
            dosHeader->e_magic = 0x0000; // Clear MZ signature
            VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), oldProtect, &oldProtect);
            return true;
        }
        
        return false;
    }

    bool MemoryProtection::scrambleHeaders() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

        DWORD oldProtect;
        if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
            // Scramble NT signature
            ntHeaders->Signature = 0x00000000;
            VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
            return true;
        }

        return false;
    }

    bool MemoryProtection::protectCriticalSections() {
        // Add integrity protection for critical code sections
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
        IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                uintptr_t sectionAddr = (uintptr_t)hModule + sectionHeader[i].VirtualAddress;
                size_t sectionSize = sectionHeader[i].Misc.VirtualSize;
                
                std::string sectionName = std::string((char*)sectionHeader[i].Name, 8);
                addIntegrityRegion(sectionAddr, sectionSize, sectionName);
            }
        }

        return true;
    }

    uint32_t MemoryProtection::calculateRegionHash(uintptr_t address, size_t size) {
        auto data = rgs::sdk::memory::readBuffer(address, size);
        return rgs::sdk::security::computeCrc32(data);
    }

    bool MemoryProtection::isRegionModified(const MemoryIntegrityRegion& region) {
        uint32_t currentHash = calculateRegionHash(region.startAddress, region.size);
        return currentHash != region.originalHash;
    }

    bool MemoryProtection::isAddressHooked(uintptr_t address) {
        // Read first few bytes to check for hook patterns
        auto data = rgs::sdk::memory::readBuffer(address, 16);
        if (data.empty()) return false;

        // Check for common hook patterns
        // JMP (E9), CALL (E8), PUSH+RET
        if (data[0] == std::byte{0xE9} || data[0] == std::byte{0xE8}) {
            return true; // Jump or call hook
        }

        // Check for PUSH + RET pattern
        if (data[0] == std::byte{0x68} && data.size() >= 6 && data[5] == std::byte{0xC3}) {
            return true; // Push address + ret
        }

        return false;
    }

    bool MemoryProtection::checkImportTable() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
            return false;
        }

        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name != 0) {
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->FirstThunk);
            
            while (thunk->u1.Function != 0) {
                // Check if the function pointer points to expected module range
                HMODULE hTargetModule = NULL;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
                                      (LPCSTR)thunk->u1.Function, &hTargetModule)) {
                    
                    // If the function doesn't point to a loaded module, it might be hooked
                    if (!hTargetModule) {
                        return true;
                    }
                }
                thunk++;
            }
            importDesc++;
        }

        return false;
    }

    bool MemoryProtection::checkExportTable() {
        // Similar to import table check but for exports
        return false;
    }

    bool MemoryProtection::validateExecutableCode(uintptr_t address, size_t size) {
        // Read the code and perform basic validation
        auto data = rgs::sdk::memory::readBuffer(address, std::min(size, static_cast<size_t>(1024)));
        if (data.empty()) return false;

        // Check for valid x86/x64 instructions at the beginning
        // This is a simplified check
        if (data.size() >= 2) {
            // Look for common instruction patterns
            std::byte firstByte = data[0];
            
            // Valid instruction prefixes and opcodes
            if (firstByte == std::byte{0x48} || // REX prefix (x64)
                firstByte == std::byte{0x55} || // PUSH EBP
                firstByte == std::byte{0x8B} || // MOV
                firstByte == std::byte{0x83} || // ADD/SUB/CMP
                firstByte == std::byte{0xFF}) { // CALL/JMP
                return true;
            }
        }

        return false;
    }

    LONG WINAPI MemoryProtection::vectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        if (!g_instance) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
            // Log the access attempt
            MemoryThreatDetection threat;
            threat.type = MemoryThreat::IllegalAccess;
            threat.address = reinterpret_cast<uintptr_t>(pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
            threat.size = 0;
            threat.description = "Illegal memory access detected";
            g_instance->m_detectedThreats.push_back(threat);

            // Restore the page guard
            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<LPVOID>(threat.address), 1, 
                          PAGE_READONLY | PAGE_GUARD, &oldProtect);

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool MemoryProtection::setupPageGuards() {
        // Setup page guards on critical regions
        for (const auto& [name, region] : m_protectedRegions) {
            DWORD oldProtect;
            if (!VirtualProtect(reinterpret_cast<LPVOID>(region.startAddress), 
                               region.size, PAGE_READONLY | PAGE_GUARD, &oldProtect)) {
                return false;
            }
        }
        return true;
    }

    void MemoryProtection::removePageGuards() {
        // Remove page guards
        for (const auto& [name, region] : m_protectedRegions) {
            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<LPVOID>(region.startAddress), 
                          region.size, region.originalProtection, &oldProtect);
        }
    }

} // namespace rgs::sdk::protection