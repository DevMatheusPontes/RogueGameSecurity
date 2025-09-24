#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <optional>
#include <unordered_map>

namespace rgs::sdk::protection {

    enum class MemoryThreat {
        Unknown,
        DumpAttempt,
        MemoryPatch,
        HookInjection,
        CodeInjection,
        IllegalAccess,
        IntegrityViolation
    };

    struct MemoryIntegrityRegion {
        uintptr_t startAddress;
        size_t size;
        uint32_t originalHash;
        DWORD originalProtection;
        bool isProtected;
        std::string name;
    };

    struct MemoryThreatDetection {
        MemoryThreat type;
        uintptr_t address;
        size_t size;
        std::string description;
        std::vector<std::byte> suspiciousData;
    };

    class MemoryProtection {
    public:
        MemoryProtection();
        ~MemoryProtection();

        // Initialize memory protection
        bool initialize();
        void shutdown();

        // Anti-dump protection
        bool enableAntiDump();
        void disableAntiDump();
        bool isAntiDumpEnabled() const;

        // Memory integrity protection
        bool addIntegrityRegion(uintptr_t address, size_t size, const std::string& name);
        bool removeIntegrityRegion(const std::string& name);
        bool verifyIntegrity();
        std::vector<MemoryThreatDetection> checkIntegrityViolations();

        // Hook detection
        bool scanForHooks();
        std::vector<MemoryThreatDetection> detectHooks();
        bool removeDetectedHooks();

        // Memory access monitoring
        bool enableAccessMonitoring();
        void disableAccessMonitoring();
        std::vector<MemoryThreatDetection> getAccessViolations();

        // Code injection detection
        bool detectCodeInjection();
        std::vector<MemoryThreatDetection> scanForInjectedCode();

        // Memory patching detection
        bool detectMemoryPatches();
        std::vector<MemoryThreatDetection> scanForPatches();

        // Protection configuration
        void setProtectionLevel(int level); // 1-5, 5 being highest
        int getProtectionLevel() const;
        void setStealthMode(bool enabled);

    private:
        // Anti-dump implementation
        bool hidePEHeader();
        bool scrambleHeaders();
        bool protectCriticalSections();
        
        // Memory integrity helpers
        uint32_t calculateRegionHash(uintptr_t address, size_t size);
        bool isRegionModified(const MemoryIntegrityRegion& region);
        void updateRegionHash(MemoryIntegrityRegion& region);

        // Hook detection helpers
        bool isAddressHooked(uintptr_t address);
        bool checkImportTable();
        bool checkExportTable();
        bool scanInlineHooks();
        
        // Access monitoring
        static LONG WINAPI vectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);
        bool setupPageGuards();
        void removePageGuards();
        
        // Code injection helpers
        bool scanExecutableRegions();
        bool validateExecutableCode(uintptr_t address, size_t size);
        
        // Memory patch helpers
        bool compareWithDiskImage();
        bool scanForNopSleds();
        bool detectRuntimePatches();

        // Configuration
        bool m_antiDumpEnabled = false;
        bool m_integrityCheckEnabled = true;
        bool m_hookDetectionEnabled = true;
        bool m_accessMonitoringEnabled = false;
        bool m_stealthMode = false;
        int m_protectionLevel = 3;
        
        // State
        bool m_initialized = false;
        PVOID m_vehHandler = nullptr;
        
        // Protected regions
        std::unordered_map<std::string, MemoryIntegrityRegion> m_protectedRegions;
        
        // Detected threats
        std::vector<MemoryThreatDetection> m_detectedThreats;
        
        // Original PE sections for comparison
        std::vector<std::pair<uintptr_t, std::vector<std::byte>>> m_originalSections;
    };

} // namespace rgs::sdk::protection
