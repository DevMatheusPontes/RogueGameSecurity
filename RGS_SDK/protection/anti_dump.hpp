#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

struct DumpDetection {
    std::string method;
    std::string description;
    uintptr_t   address;
    size_t      size;
    bool        isSuspicious;
};

class AntiDump {
public:
    AntiDump();
    ~AntiDump();

    // Inicialização / encerramento
    bool initialize();
    void shutdown();

    // Habilita proteção abrangente de anti-dump
    bool enable_protection();
    void disable_protection();

    bool is_enabled() const;

    // Configurações
    void set_patch_dump_apis(bool enable);
    void set_obfuscate_headers(bool enable);
    void set_obfuscate_sections(bool enable);
    void set_memory_hardening(bool enable);

    // Scans / detecções
    std::vector<DumpDetection> scan_dump_tools();
    std::vector<DumpDetection> scan_dbghelp_presence();
    std::vector<DumpDetection> scan_suspicious_files();
    std::vector<DumpDetection> scan_memory_staging();

    bool detectDumpAttempt();

private:
    // Aplicadores de proteção
    bool patch_dump_related_apis();
    bool obfuscate_pe_headers();
    bool obfuscate_sensitive_sections();
    bool harden_memory_regions();
    bool apply_process_mitigations();

    // Helpers
    bool patch_api(const char* module, const char* func);
    bool protect_region(void* base, size_t size, DWORD newProt);
    bool zero_memory(void* base, size_t size);

    // PE helpers
    bool get_module_info(HMODULE mod, uintptr_t& base, size_t& size);
    bool obfuscate_module_headers(HMODULE mod);
    bool obfuscate_module_sections(HMODULE mod, const std::vector<std::string>& names);

    // Scans auxiliares
    std::vector<HMODULE> list_modules();
    bool is_dbghelp_loaded();
    bool is_minidump_export_present(HMODULE mod);
    bool match_dump_filename(const std::wstring& path);

private:
    std::atomic<bool> enabled_{false};
    std::atomic<bool> patch_dump_apis_{true};
    std::atomic<bool> obfuscate_headers_{true};
    std::atomic<bool> obfuscate_sections_{true};
    std::atomic<bool> memory_hardening_{true};

    // Cache simples de última varredura
    std::vector<DumpDetection> last_tools_;
    std::vector<DumpDetection> last_dbghelp_;
    std::vector<DumpDetection> last_files_;
    std::vector<DumpDetection> last_memory_;
};

} // namespace rgs::sdk::protection
