#include "anti_inject.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <optional>
#include <cstring>

namespace rgs::sdk::protection {

// NtQueryInformationThread - ThreadQuerySetWin32StartAddress (9)
using NtQIT = NTSTATUS(WINAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
static uintptr_t QueryThreadStart(HANDLE hThread) {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn    = reinterpret_cast<NtQIT>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    if (!fn) return 0;

    PVOID start = nullptr;
    NTSTATUS st = fn(hThread, (THREADINFOCLASS)9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
    if (st == 0) return reinterpret_cast<uintptr_t>(start);
    return 0;
}

AntiInject::AntiInject() = default;
AntiInject::~AntiInject() = default;

bool AntiInject::initialize() { return true; }
void  AntiInject::shutdown()  {}

bool AntiInject::readBytes(uintptr_t addr, void* out, size_t len) {
    SIZE_T rd = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), out, len, &rd) && rd == len;
}

std::optional<AntiInject::RegionInfo> AntiInject::getRegionInfo(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        return std::nullopt;
    RegionInfo ri{};
    ri.base   = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    ri.size   = mbi.RegionSize;
    ri.protect= mbi.Protect;
    ri.state  = mbi.State;
    ri.type   = mbi.Type;
    return ri;
}

bool AntiInject::isPEImageAt(uintptr_t addr) {
    IMAGE_DOS_HEADER dos{};
    if (!readBytes(addr, &dos, sizeof(dos))) return false;
    if (dos.e_magic != 0x5A4D /*MZ*/) return false;

    IMAGE_NT_HEADERS nt{};
    uintptr_t ntAddr = addr + static_cast<uintptr_t>(dos.e_lfanew);
    if (!readBytes(ntAddr, &nt, sizeof(nt))) return false;
    if (nt.Signature != 0x00004550 /*PE\0\0*/) return false;

    // sanity minimal checks
    if (nt.FileHeader.NumberOfSections == 0 || nt.OptionalHeader.SizeOfImage < 0x1000) return false;
    return true;
}

bool AntiInject::isLikelyShellcode(const uint8_t* b, size_t n) {
    if (n < 16) return false;
    // heurísticas simples: presença de opcodes comuns de shellcode
    size_t hits = 0;
    for (size_t i=0;i<n;i++) {
        uint8_t op = b[i];
        if (op == 0xCC || op == 0xE9 || op == 0x68 || op == 0x6A || op == 0xC3 || op == 0x90) {
            hits++;
        }
    }
    return hits > n/20; // >5% opcodes suspeitos
}

bool AntiInject::isRWX(DWORD prot) const {
    return (prot & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE;
}

bool AntiInject::isRX(DWORD prot) const {
    return (prot & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ;
}

std::vector<AntiInject::ModuleInfo> AntiInject::getLoadedModules() {
    std::vector<ModuleInfo> mods;
    HMODULE arr[1024];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();

    if (!EnumProcessModules(proc, arr, sizeof(arr), &needed)) return mods;
    size_t count = needed / sizeof(HMODULE);
    mods.reserve(count);

    for (size_t i=0;i<count;i++) {
        MODULEINFO mi{};
        char path[MAX_PATH] = {};
        if (GetModuleInformation(proc, arr[i], &mi, sizeof(mi)) &&
            GetModuleFileNameExA(proc, arr[i], path, sizeof(path))) {
            ModuleInfo info{};
            info.handle = arr[i];
            info.base   = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            info.size   = static_cast<size_t>(mi.SizeOfImage);
            info.path   = path;
            mods.push_back(info);
        }
    }
    // ordenar por base
    std::sort(mods.begin(), mods.end(), [](const ModuleInfo& a, const ModuleInfo& b){ return a.base < b.base; });
    return mods;
}

std::vector<AntiInject::ModuleInfo> AntiInject::getPEBLdrModules() {
    std::vector<ModuleInfo> mods;
#ifdef _M_X64
    // PEB->Ldr->InMemoryOrder list
    PPEB peb = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
    PPEB peb = (PPEB)__readfsdword(0x30);
#else
    return mods;
#endif
    if (!peb || !peb->Ldr) return mods;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        auto data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        ModuleInfo info{};
        info.base = reinterpret_cast<uintptr_t>(data->DllBase);
        info.size = static_cast<size_t>(data->SizeOfImage);

        // Monta path a partir de UNICODE_STRING
        char path[MAX_PATH]{};
        int len = WideCharToMultiByte(CP_UTF8, 0,
                                      data->FullDllName.Buffer,
                                      data->FullDllName.Length / sizeof(WCHAR),
                                      path, sizeof(path)-1, nullptr, nullptr);
        if (len > 0) path[len] = '\0';
        info.path = path;
        info.handle = reinterpret_cast<HMODULE>(data->DllBase);

        mods.push_back(info);
        curr = curr->Flink;
    }
    std::sort(mods.begin(), mods.end(), [](const ModuleInfo& a, const ModuleInfo& b){ return a.base < b.base; });
    return mods;
}

bool AntiInject::moduleRangesEqual(const ModuleInfo& a, const ModuleInfo& b) const {
    return a.base == b.base && a.size == b.size;
}

bool AntiInject::isAddressInAnyModule(uintptr_t addr, const std::vector<ModuleInfo>& mods) {
    for (const auto& m : mods) {
        if (addr >= m.base && addr < (m.base + m.size)) return true;
    }
    return false;
}

uintptr_t AntiInject::getThreadStartAddress(HANDLE hThread) {
    return QueryThreadStart(hThread);
}

// ————————————————— Scans principais —————————————————

std::vector<InjectionDetection> AntiInject::collectThreadsInternal(const std::vector<ModuleInfo>& mods) {
    std::vector<InjectionDetection> out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();

    auto addDet = [&](const char* method, const char* desc, uintptr_t addr, bool susp) {
        InjectionDetection d{ method, desc, addr, 0, susp };
        out.push_back(d);
    };

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;

            uintptr_t start = getThreadStartAddress(th);
            CloseHandle(th);

            if (start == 0) {
                addDet("ThreadScan", "Falha ao obter StartAddress", start, true);
                continue;
            }

            if (!isAddressInAnyModule(start, mods)) {
                addDet("ThreadHijack", "StartAddress fora de módulos conhecidos (possível hijack)", start, true);
            }

        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return out;
}

std::vector<InjectionDetection> AntiInject::collectRegionsInternal(const std::vector<ModuleInfo>& mods) {
    std::vector<InjectionDetection> out;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    HANDLE proc = GetCurrentProcess();

    auto addDet = [&](const char* method, const char* desc, uintptr_t base, size_t size, bool susp) {
        InjectionDetection d{ method, desc, base, size, susp };
        out.push_back(d);
    };

    while (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        bool committed = (mbi.State == MEM_COMMIT);
        bool exec      = isRX(mbi.Protect) || isRWX(mbi.Protect);

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t    size = mbi.RegionSize;

        if (committed && exec) {
            bool inModule = isAddressInAnyModule(base, mods);
            // lê alguns bytes para heurística
            size_t sample = size > 256 ? 256 : size;
            std::vector<uint8_t> buf(sample);
            SIZE_T rd = 0;
            bool ok = ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), buf.size(), &rd) && rd == buf.size();

            if (!inModule) {
                if (ok && isLikelyShellcode(buf.data(), buf.size())) {
                    addDet("MemoryScan", "Região executável fora de módulos com padrões de shellcode", base, size, true);
                } else {
                    addDet("MemoryScan", "Região executável fora de módulos", base, size, true);
                }
            } else if (isRWX(mbi.Protect)) {
                addDet("MemoryScan", "Região RXW dentro de módulo (provável patch/hook)", base, size, true);
            }
        }

        addr += mbi.RegionSize;
    }

    return out;
}

std::vector<InjectionDetection> AntiInject::collectManualMappedInternal(const std::vector<ModuleInfo>& mods) {
    std::vector<InjectionDetection> out;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    HANDLE proc = GetCurrentProcess();

    auto addDet = [&](const char* method, const char* desc, uintptr_t base, size_t size, bool susp) {
        InjectionDetection d{ method, desc, base, size, susp };
        out.push_back(d);
    };

    while (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        bool committed = (mbi.State == MEM_COMMIT);
        bool readable  = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t    size = mbi.RegionSize;

        if (committed && readable) {
            if (isPEImageAt(base)) {
                // Se parece um PE e não está na lista de módulos, suspeito de manual mapping
                if (!isAddressInAnyModule(base, mods)) {
                    addDet("ManualMap", "PE válido em memória fora da lista de módulos (manual mapping)", base, size, true);
                }
            }
        }

        addr += mbi.RegionSize;
    }

    return out;
}

std::vector<InjectionDetection> AntiInject::scanSuspiciousThreads() {
    auto mods = getLoadedModules();
    lastSuspiciousThreads_ = collectThreadsInternal(mods);
    return lastSuspiciousThreads_;
}

std::vector<InjectionDetection> AntiInject::scanMemoryRegions() {
    auto mods = getLoadedModules();
    auto regs = collectRegionsInternal(mods);
    return regs;
}

std::vector<InjectionDetection> AntiInject::scanManualMappedImages() {
    auto mods = getLoadedModules();
    auto man  = collectManualMappedInternal(mods);
    lastSuspiciousModules_ = man;
    return man;
}

std::vector<InjectionDetection> AntiInject::scanUnlinkedModules() {
    // Compara EnumProcessModules com PEB Ldr. Diferenças sugerem unlinked/hide
    std::vector<InjectionDetection> out;
    auto enumMods = getLoadedModules();
    auto ldrMods  = getPEBLdrModules();

    // Para cada módulo do PEB Ldr, verifique se aparece em EnumProcessModules
    for (const auto& lm : ldrMods) {
        bool found = false;
        for (const auto& em : enumMods) {
            if (moduleRangesEqual(lm, em)) { found = true; break; }
        }
        if (!found) {
            InjectionDetection d{
                "UnlinkedModule",
                "Módulo presente em Ldr mas ausente em EnumProcessModules (hidden/unlinked)",
                lm.base,
                lm.size,
                true
            };
            out.push_back(d);
        }
    }
    return out;
}

// ————————————————— Detecções agregadas —————————————————

bool AntiInject::detectManualMapping() {
    auto res = scanManualMappedImages();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

bool AntiInject::detectThreadHijacking() {
    auto res = scanSuspiciousThreads();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

bool AntiInject::detectShellcode() {
    auto res = scanMemoryRegions();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

bool AntiInject::detectUnlinkedModules() {
    auto res = scanUnlinkedModules();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

// ————————————————— Resposta ativa —————————————————

void AntiInject::terminateSuspiciousThreads() {
    if (lastSuspiciousThreads_.empty()) scanSuspiciousThreads();
    for (const auto& t : lastSuspiciousThreads_) {
        if (!t.isSuspicious || t.address == 0) continue;
        // Aqui t.address armazena o start address, não o handle.
        // Precisamos enumerar novamente para encontrar o thread pelo start address.
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        THREADENTRY32 te{ sizeof(te) };
        DWORD pid = GetCurrentProcessId();

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_TERMINATE, FALSE, te.th32ThreadID);
                if (!th) continue;
                uintptr_t start = getThreadStartAddress(th);
                if (start == t.address) {
                    TerminateThread(th, 0);
                    CloseHandle(th);
                    break;
                }
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
}

void AntiInject::unloadSuspiciousModules() {
    if (lastSuspiciousModules_.empty()) scanManualMappedImages();
    for (const auto& m : lastSuspiciousModules_) {
        if (!m.isSuspicious) continue;
        // Para PE manualmente mapeado, FreeLibrary não funciona (não há loader state).
        // Tentativa de proteção básica: alterar proteção para não-executável
        auto ri = getRegionInfo(m.address);
        if (ri && (ri->state == MEM_COMMIT)) {
            DWORD oldProt = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(ri->base), ri->size, PAGE_READWRITE, &oldProt);
            // Opcional: ZeroMemory de cabeçalhos (não recomendado, pode crashar).
        }
    }
}

} // namespace rgs::sdk::protection
