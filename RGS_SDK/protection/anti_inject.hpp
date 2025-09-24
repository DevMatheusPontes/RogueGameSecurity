#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace rgs::sdk::protection {

    struct InjectionDetection {
        std::string method;
        std::string description;
        uintptr_t   address;
        size_t      size;
        bool        isSuspicious;
    };

    class AntiInject {
    public:
        AntiInject();
        ~AntiInject();

        bool initialize();
        void shutdown();

        // Scans principais
        std::vector<InjectionDetection> scanInjectedModules();
        std::vector<InjectionDetection> scanSuspiciousThreads();
        std::vector<InjectionDetection> scanMemoryRegions();
        std::vector<InjectionDetection> scanUnlinkedModules();
        std::vector<InjectionDetection> scanManualMappedImages();

        // Detecções agregadas
        bool detectManualMapping();      // PE em memória sem estar nos módulos
        bool detectThreadHijacking();    // Threads com start fora de módulos
        bool detectShellcode();          // RWX/RX sem módulo e padrões de shellcode
        bool detectUnlinkedModules();    // Módulos não presentes nas listas Ldr/Enum

        // Ações de resposta (use com cautela)
        void terminateSuspiciousThreads();
        void unloadSuspiciousModules();

    private:
        // Helpers
        struct ModuleInfo {
            HMODULE   handle;
            uintptr_t base;
            size_t    size;
            std::string path;
        };

        struct RegionInfo {
            uintptr_t base;
            size_t    size;
            DWORD     protect;
            DWORD     state;
            DWORD     type;
        };

        // Lista de módulos carregados (EnumProcessModules + PEB/Ldr)
        std::vector<ModuleInfo> getLoadedModules();
        std::vector<ModuleInfo> getPEBLdrModules();

        // Thread helpers
        uintptr_t getThreadStartAddress(HANDLE hThread);
        bool      isAddressInAnyModule(uintptr_t addr, const std::vector<ModuleInfo>& mods);
        std::optional<RegionInfo> getRegionInfo(uintptr_t addr);

        // Memória helpers
        bool readBytes(uintptr_t addr, void* out, size_t len);
        bool isPEImageAt(uintptr_t addr);
        bool isLikelyShellcode(const uint8_t* buf, size_t len);
        bool isRWX(DWORD prot) const;
        bool isRX(DWORD prot) const;

        // Comparações Ldr/Enum
        bool moduleRangesEqual(const ModuleInfo& a, const ModuleInfo& b) const;

        // Coleta agregada
        std::vector<InjectionDetection> collectThreadsInternal(const std::vector<ModuleInfo>& mods);
        std::vector<InjectionDetection> collectRegionsInternal(const std::vector<ModuleInfo>& mods);
        std::vector<InjectionDetection> collectManualMappedInternal(const std::vector<ModuleInfo>& mods);

        // Cache simples
        std::vector<InjectionDetection> lastSuspiciousThreads_;
        std::vector<InjectionDetection> lastSuspiciousModules_;
    };

} // namespace rgs::sdk::protection
