#include "anti_dump.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <optional>

namespace rgs::sdk::protection {

AntiDump::AntiDump() = default;
AntiDump::~AntiDump() { shutdown(); }

bool AntiDump::initialize() {
    return true;
}

void AntiDump::shutdown() {
    disable_protection();
}

void AntiDump::set_patch_dump_apis(bool enable)      { patch_dump_apis_ = enable; }
void AntiDump::set_obfuscate_headers(bool enable)    { obfuscate_headers_ = enable; }
void AntiDump::set_obfuscate_sections(bool enable)   { obfuscate_sections_ = enable; }
void AntiDump::set_memory_hardening(bool enable)     { memory_hardening_ = enable; }
bool AntiDump::is_enabled() const                    { return enabled_.load(); }

bool AntiDump::enable_protection() {
    bool ok = true;

    if (patch_dump_apis_)    ok &= patch_dump_related_apis();
    if (obfuscate_headers_)  ok &= obfuscate_pe_headers();
    if (obfuscate_sections_) ok &= obfuscate_sensitive_sections();
    if (memory_hardening_)   ok &= harden_memory_regions();

    ok &= apply_process_mitigations(); // melhor esforço

    enabled_ = ok;
    return ok;
}

void AntiDump::disable_protection() {
    enabled_ = false;
}

// ——————————————————————————— Scans / detecções ———————————————————————————

std::vector<DumpDetection> AntiDump::scan_dump_tools() {
    std::vector<DumpDetection> out;

    // Processos conhecidos que realizam dumps
    static const char* procs[] = {
        "procdump.exe", "dumpit.exe", "x64dbg.exe", "windbg.exe", "ollydbg.exe", "cheatengine.exe"
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe{ sizeof(pe) };

    auto add = [&](const char* method, const char* desc, bool susp) {
        out.push_back({ method, desc, 0, 0, susp });
    };

    for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
        std::string name(pe.szExeFile);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        for (auto p : procs) {
            if (name.find(p) != std::string::npos) {
                add("DumpTool.Process", ("Processo suspeito: " + name).c_str(), true);
            }
        }
    }
    CloseHandle(snap);

    // Janelas conhecidas de ferramentas
    static const char* classes[] = { "WinDbgFrameClass", "OLLYDBG", "Qt5QWindowIcon", "x64dbg", "ID" };
    for (auto c : classes) {
        if (FindWindowA(c, nullptr)) {
            out.push_back({ "DumpTool.Window", std::string("Janela de ferramenta: ") + c, 0, 0, true });
        }
    }

    last_tools_ = out;
    return out;
}

std::vector<DumpDetection> AntiDump::scan_dbghelp_presence() {
    std::vector<DumpDetection> out;

    auto mods = list_modules();
    for (auto m : mods) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(m, path, sizeof(path));
        std::string spath(path);
        std::transform(spath.begin(), spath.end(), spath.begin(), ::tolower);
        if (spath.find("dbghelp.dll") != std::string::npos) {
            out.push_back({ "DbgHelp", "dbghelp.dll carregado no processo", reinterpret_cast<uintptr_t>(m), 0, true });
            if (is_minidump_export_present(m)) {
                out.push_back({ "MiniDumpWriteDump", "Export de MiniDumpWriteDump presente", reinterpret_cast<uintptr_t>(m), 0, true });
            }
        }
    }

    last_dbghelp_ = out;
    return out;
}

std::vector<DumpDetection> AntiDump::scan_suspicious_files() {
    std::vector<DumpDetection> out;

    // Observação: sem filesystem hooks, aqui usamos heurística de módulos e dbghelp.
    // Alternativa: instalar hook em CreateFileW para detectar nomes suspeitos.
    // Para efeito de detecção offline, apenas indicamos presença de dbghelp como proxy.

    if (is_dbghelp_loaded()) {
        out.push_back({ "File.Heuristic", "dbghelp presente: provável tentativa de gerar dump", 0, 0, true });
    }

    last_files_ = out;
    return out;
}

std::vector<DumpDetection> AntiDump::scan_memory_staging() {
    std::vector<DumpDetection> out;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    HANDLE proc = GetCurrentProcess();

    auto add = [&](const char* method, const char* desc, uintptr_t base, size_t size, bool susp) {
        out.push_back({ method, desc, base, size, susp });
    };

    while (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        bool committed = (mbi.State == MEM_COMMIT);
        bool writable  = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
        bool large     = mbi.RegionSize >= (1 << 20); // regiões >= 1MB

        if (committed && writable && large) {
            add("Memory.Staging", "Região grande e gravável (possível staging de dump)", (uintptr_t)mbi.BaseAddress, mbi.RegionSize, true);
        }
        addr += mbi.RegionSize;
    }

    last_memory_ = out;
    return out;
}

bool AntiDump::detectDumpAttempt() {
    auto t = scan_dump_tools();
    auto d = scan_dbghelp_presence();
    auto f = scan_suspicious_files();
    auto m = scan_memory_staging();

    auto anySusp = [&](const std::vector<DumpDetection>& v) {
        return std::any_of(v.begin(), v.end(), [](auto& e){ return e.isSuspicious; });
    };
    return anySusp(t) || anySusp(d) || anySusp(f) || anySusp(m);
}

// ——————————————————————————— Aplicadores de proteção ———————————————————————————

bool AntiDump::patch_dump_related_apis() {
    bool ok = true;
    // DbgHelp: MiniDumpWriteDump
    ok &= patch_api("dbghelp.dll", "MiniDumpWriteDump");

    // Kernel32: CreateFileW (nome de arquivo típico de dump)
    ok &= patch_api("kernel32.dll", "CreateFileW");

    // Ntdll: RtlCaptureContext (usado em várias rotinas de coleta de contexto para dump)
    ok &= patch_api("ntdll.dll", "RtlCaptureContext");

    // Ntdll: NtQueryInformationProcess (PSS capture / ProcessInfo dump)
    ok &= patch_api("ntdll.dll", "NtQueryInformationProcess");

    return ok;
}

bool AntiDump::obfuscate_pe_headers() {
    // Ofusca cabeçalhos do módulo principal (e opcionalmente de módulos críticos)
    HMODULE self = GetModuleHandleA(nullptr);
    if (self) {
        if (!obfuscate_module_headers(self)) return false;
    }

    // Opcional: ofuscar cabeçalhos de outras DLLs sensíveis (ex.: seu cliente RGS)
    auto mods = list_modules();
    for (auto m : mods) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(m, path, sizeof(path));
        std::string sp(path);
        std::transform(sp.begin(), sp.end(), sp.begin(), ::tolower);
        // exemplo: ofusca cabeçalho de sua DLL "rgs_client.dll"
        if (sp.find("rgs_client.dll") != std::string::npos) {
            obfuscate_module_headers(m);
        }
    }
    return true;
}

bool AntiDump::obfuscate_sensitive_sections() {
    // Exemplo: ofusca .pdata, .rsrc, .reloc (menos críticos para execução, mas úteis para análise)
    static const std::vector<std::string> targets = { ".pdata", ".rsrc", ".reloc" };

    HMODULE self = GetModuleHandleA(nullptr);
    if (self) obfuscate_module_sections(self, targets);

    auto mods = list_modules();
    for (auto m : mods) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(m, path, sizeof(path));
        std::string sp(path);
        std::transform(sp.begin(), sp.end(), sp.begin(), ::tolower);
        if (sp.find("rgs_client.dll") != std::string::npos) {
            obfuscate_module_sections(m, targets);
        }
    }
    return true;
}

bool AntiDump::harden_memory_regions() {
    // Estratégia simples: evitar PAGE_EXECUTE_READWRITE em regiões grandes
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    HANDLE proc = GetCurrentProcess();
    bool changed = false;

    while (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= (1 << 20)) { // >= 1MB
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                DWORD old = 0;
                if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &old)) {
                    changed = true;
                }
            }
        }
        addr += mbi.RegionSize;
    }
    return changed || true;
}

bool AntiDump::apply_process_mitigations() {
    // Em versões modernas do Windows, algumas políticas podem ajudar:
    // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE
    // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    // Aqui usamos melhor-esforço; a API pode não existir.
    typedef BOOL (WINAPI* SetProcMitigation)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    auto kernel = GetModuleHandleA("kernel32.dll");
    if (!kernel) return true;
    auto setMit = (SetProcMitigation)GetProcAddress(kernel, "SetProcessMitigationPolicy");
    if (!setMit) return true;

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{};
    dyn.ProhibitDynamicCode = 1;
    setMit(ProcessDynamicCodePolicy, &dyn, sizeof(dyn));

    // Bloqueia export address table acessos (parcial)
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    sig.MicrosoftSignedOnly = 0; // ajustar conforme política
    setMit(ProcessSignaturePolicy, &sig, sizeof(sig));

    return true;
}

// ——————————————————————————— Helpers ———————————————————————————

bool AntiDump::patch_api(const char* module, const char* func) {
    HMODULE h = GetModuleHandleA(module);
    if (!h) return false;
    FARPROC f = GetProcAddress(h, func);
    if (!f) return false;

    DWORD oldProt = 0;
    if (!VirtualProtect((LPVOID)f, 8, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    BYTE ret = 0xC3; // RET
    std::memcpy((void*)f, &ret, 1);
    VirtualProtect((LPVOID)f, 8, oldProt, &oldProt);
    return true;
}

bool AntiDump::protect_region(void* base, size_t size, DWORD newProt) {
    DWORD old = 0;
    return VirtualProtect(base, size, newProt, &old) != 0;
}

bool AntiDump::zero_memory(void* base, size_t size) {
    __try {
        std::memset(base, 0, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool AntiDump::get_module_info(HMODULE mod, uintptr_t& base, size_t& size) {
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return false;
    base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    size = static_cast<size_t>(mi.SizeOfImage);
    return true;
}

bool AntiDump::obfuscate_module_headers(HMODULE mod) {
    uintptr_t base; size_t size;
    if (!get_module_info(mod, base, size)) return false;

    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != 0x5A4D /*MZ*/) return false;

    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550 /*PE\0\0*/) return false;

    // Ofusca DOS stub e parte do NT headers (campos não críticos)
    protect_region((void*)base, 0x1000, PAGE_READWRITE);
    zero_memory((void*)base, sizeof(IMAGE_DOS_HEADER)); // cuidado: pode quebrar ferramentas
    // Ofusca data directories menos críticos para execução
    auto& opt = nt->OptionalHeader;
    auto dirCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    for (UINT i = 0; i < dirCount; ++i) {
        // zera diretórios como DEBUG/EXCEPTION/CLR
        if (i == IMAGE_DIRECTORY_ENTRY_DEBUG ||
            i == IMAGE_DIRECTORY_ENTRY_EXCEPTION ||
            i == IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            opt.DataDirectory[i].VirtualAddress = 0;
            opt.DataDirectory[i].Size = 0;
        }
    }
    return true;
}

bool AntiDump::obfuscate_module_sections(HMODULE mod, const std::vector<std::string>& names) {
    uintptr_t base; size_t size;
    if (!get_module_info(mod, base, size)) return false;

    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != 0x5A4D) return false;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return false;

    auto sec = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char name[9]{};
        std::memcpy(name, sec[i].Name, 8);
        std::string sname(name);
        // normaliza
        std::transform(sname.begin(), sname.end(), sname.begin(), ::tolower);

        for (const auto& target : names) {
            std::string t = target; std::transform(t.begin(), t.end(), t.begin(), ::tolower);
            if (sname == t) {
                void* sbase = (void*)(base + sec[i].VirtualAddress);
                size_t ssize = sec[i].SizeOfRawData ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
                protect_region(sbase, ssize, PAGE_READWRITE);
                zero_memory(sbase, ssize / 2); // zera metade como ofuscação leve
            }
        }
    }
    return true;
}

std::vector<HMODULE> AntiDump::list_modules() {
    std::vector<HMODULE> mods;
    HMODULE arr[1024]; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), arr, sizeof(arr), &needed)) return mods;
    size_t count = needed / sizeof(HMODULE);
    mods.assign(arr, arr + count);
    return mods;
}

bool AntiDump::is_dbghelp_loaded() {
    auto mods = list_modules();
    for (auto m : mods) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(m, path, sizeof(path));
        std::string sp(path);
        std::transform(sp.begin(), sp.end(), sp.begin(), ::tolower);
        if (sp.find("dbghelp.dll") != std::string::npos) return true;
    }
    return false;
}

bool AntiDump::is_minidump_export_present(HMODULE mod) {
    FARPROC f = GetProcAddress(mod, "MiniDumpWriteDump");
    return f != nullptr;
}

bool AntiDump::match_dump_filename(const std::wstring& path) {
    // Heurística simples: nomes comuns de dump
    static const wchar_t* patterns[] = { L".dmp", L"dump", L"minidump", L"processdump" };
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (auto p : patterns) {
        if (lower.find(p) != std::wstring::npos) return true;
    }
    return false;
}

} // namespace rgs::sdk::protection
