#include "anti_debug.hpp"
#include <intrin.h>
#include <psapi.h>
#include <winternl.h>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>

// Prototypes para NtQueryInformationProcess / NtQuerySystemInformation
using NtQIP = NTSTATUS(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQSI = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);

namespace rgs::sdk::protection {

AntiDebug::AntiDebug()  = default;
AntiDebug::~AntiDebug() = default;

bool AntiDebug::initialize() {
    m_initialized = true;
    return true;
}

void AntiDebug::shutdown() {
    m_initialized = false;
}

void AntiDebug::setProtectionEnabled(bool enabled) {
    m_enabled = enabled;
}

bool AntiDebug::isProtectionEnabled() const {
    return m_enabled;
}

bool AntiDebug::isBeingDebugged() {
    if (!m_initialized || !m_enabled) return false;
    auto det = scanForDebuggers();
    return std::any_of(det.begin(), det.end(), [](auto& d){ return d.isActive; });
}

std::vector<DebugDetection> AntiDebug::scanForDebuggers() {
    std::vector<DebugDetection> results;
    auto add = [&](DebuggerType t, const std::string& m, const std::string& d, bool a) {
        results.push_back({t,m,d,a});
    };

    add(DebuggerType::UserModeAPI,        "IsDebuggerPresent",        "Windows API IsDebuggerPresent",           checkIsDebuggerPresent());
    add(DebuggerType::UserModeAPI,        "CheckRemoteDebugger",      "Windows API CheckRemoteDebuggerPresent",  checkRemoteDebuggerPresent());
    add(DebuggerType::UserModePEB,        "PEB.BeingDebugged",        "PEB BeingDebugged flag",                  detectPEBBeingDebugged());
    add(DebuggerType::UserModeGlobalFlag, "PEB.NtGlobalFlag",        "PEB NtGlobalFlag modification",           detectPEBNtGlobalFlag());
    add(DebuggerType::UserModeHeap,       "Heap.Flags",              "Heap tail/trash checks",                  detectHeapFlags());
    add(DebuggerType::UserModePort,       "DebugPort",               "NtQueryInformationProcess DebugPort",     detectDebugPort());
    add(DebuggerType::UserModePort,       "DebugObject",             "NtQueryInformationProcess DebugObject",   detectDebugObject());
    add(DebuggerType::KernelMode,         "KernelDebugger",          "NtQuerySystemInformation KdDebugger",     detectKernelDebugger());
    add(DebuggerType::Hardware,           "Hardware.Breakpoints",    "CPU DR0-DR3 registers",                   detectHardwareBreakpoints());
    add(DebuggerType::UserModeAPI,        "INT3.Scan",               "Memory scan for 0xCC opcodes",            detectSoftwareBreakpoints());
    add(DebuggerType::UserModeTiming,     "Timing.Anomaly",          "Loop execution time anomaly",             detectTimingAnomaly());
    add(DebuggerType::UserModeTrap,       "OutputDebugString.Trap",  "Exception on OutputDebugStringA",         detectOutputDebugStringTrap());
    add(DebuggerType::UserModeWindow,     "Window.Debugger",         "FindWindow for known debugger classes",   detectDebuggerWindows());
    add(DebuggerType::UserModeProcess,    "Process.Debugger",        "Enum processes for debugger executables", detectDebuggerProcesses());
    add(DebuggerType::Hypervisor,         "CPUID.Hypervisor",        "CPU hypervisor bit",                      detectHypervisor());
    add(DebuggerType::UserModeAPI,        "Stealth.Hooks",           "Detect inline/IAT/EAT/SSDT hooks",        detectStealthHooks());
    add(DebuggerType::UserModeAPI,        "IDT.Integrity",           "Checksum of IDT entries",                 detectIDTIntegrity());

    return results;
}

// ————— Detecção por APIs Windows —————

bool AntiDebug::checkIsDebuggerPresent() {
    return ::IsDebuggerPresent() != FALSE;
}

bool AntiDebug::checkRemoteDebuggerPresent() {
    BOOL remote = FALSE;
    return ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote;
}

// ————— PEB internals —————

bool AntiDebug::detectPEBBeingDebugged() {
#ifdef _M_IX86
    DWORD peb = __readfsdword(0x30);
    return *(BYTE*)(peb + 2) != 0;
#elif defined(_M_X64)
    DWORD64 peb = __readgsqword(0x60);
    return *(BYTE*)(peb + 2) != 0;
#else
    return false;
#endif
}

bool AntiDebug::detectPEBNtGlobalFlag() {
#ifdef _M_IX86
    DWORD peb = __readfsdword(0x30);
    return ((*(DWORD*)(peb + 0x68)) & 0x70) != 0;
#elif defined(_M_X64)
    DWORD64 peb = __readgsqword(0x60);
    return ((*(DWORD*)(peb + 0xBC)) & 0x70) != 0;
#else
    return false;
#endif
}

// ————— Heap flags —————

bool AntiDebug::detectHeapFlags() {
    HANDLE h = GetProcessHeap();
    // offset 0x10 em Win10 x64
    DWORD flags = *(DWORD*)((uintptr_t)h + 0x10);
    const DWORD HEAP_TAIL_CHECKING = 0x4;
    return (flags & HEAP_TAIL_CHECKING) != 0;
}

// ————— NtQueryInformationProcess —————

bool AntiDebug::detectDebugPort() {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn    = (NtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!fn) return false;
    ULONG_PTR port = 0;
    NTSTATUS st    = fn(GetCurrentProcess(), 7, &port, sizeof(port), nullptr);
    return NT_SUCCESS(st) && port != 0;
}

bool AntiDebug::detectDebugObject() {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn    = (NtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!fn) return false;
    HANDLE obj = nullptr;
    NTSTATUS st = fn(GetCurrentProcess(), 30, &obj, sizeof(obj), nullptr);
    return NT_SUCCESS(st) && obj != nullptr;
}

// ————— Kernel debugger info —————

bool AntiDebug::detectKernelDebugger() {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn    = (NtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!fn) return false;
    struct { BOOLEAN Enabled; BOOLEAN Crashed; } info{};
    NTSTATUS st = fn(35 /*SystemKernelDebuggerInformation*/, &info, sizeof(info), nullptr);
    return NT_SUCCESS(st) && (info.Enabled || info.Crashed);
}

// ————— Hardware breakpoints —————

bool AntiDebug::detectHardwareBreakpoints() {
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return ctx.Dr0||ctx.Dr1||ctx.Dr2||ctx.Dr3;
    }
    return false;
}

// ————— Software breakpoints (INT3) —————

bool AntiDebug::detectSoftwareBreakpoints() {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    auto proc = GetCurrentProcess();

    while (VirtualQueryEx(proc,(LPCVOID)addr,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T rd;
            if (ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), buf.size(), &rd)) {
                for (SIZE_T i=0;i<rd;++i) {
                    if (buf[i]==0xCC) return true;
                }
            }
        }
        addr += mbi.RegionSize;
    }
    return false;
}

// ————— Timing anomaly —————

bool AntiDebug::detectTimingAnomaly() {
    return measureLoopTime() > 200;
}

DWORD AntiDebug::measureLoopTime(size_t it) {
    auto t0 = std::chrono::high_resolution_clock::now();
    for (volatile size_t i=0;i<it;++i);
    auto t1 = std::chrono::high_resolution_clock::now();
    return (DWORD)std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();
}

// ————— OutputDebugString trap —————

bool AntiDebug::detectOutputDebugStringTrap() {
    __try {
        OutputDebugStringA("RGS_TRAP");
        return false;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

// ————— Janela de debugger —————

bool AntiDebug::detectDebuggerWindows() {
    static const char* classes[] = {
        "OLLYDBG", "WinDbgFrameClass", "Qt5QWindowIcon", "x64dbg", "ID"
    };
    for (auto cls : classes) {
        if (FindWindowA(cls, nullptr)) return true;
    }
    return false;
}

// ————— Processos de debugger —————

bool AntiDebug::detectDebuggerProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ok=Process32First(snap,&pe); ok; ok=Process32Next(snap,&pe)) {
        std::string name(pe.szExeFile);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        static const char* procs[] = {
            "ollydbg.exe","x64dbg.exe","ida.exe","cheatengine.exe","windbg.exe"
        };
        for (auto p: procs){
            if (name.find(p)!=std::string::npos) {
                CloseHandle(snap);
                return true;
            }
        }
    }
    CloseHandle(snap);
    return false;
}

// ————— Hypervisor detection via CPUID —————

bool AntiDebug::detectHypervisor() {
    int CPUInfo[4] = { 0 };
    __cpuid(CPUInfo, 1);
    return (CPUInfo[2] & (1 << 31)) != 0;
}

// ————— Stealth hook detection (IAT/EAT/inline) —————

bool AntiDebug::detectStealthHooks() {
    HMODULE mods[1024]; DWORD cb;
    if (!EnumProcessModules(GetCurrentProcess(),mods,sizeof(mods),&cb)) return false;
    for (DWORD i=0;i<cb/sizeof(HMODULE);++i) {
        MODULEINFO mi; GetModuleInformation(GetCurrentProcess(),mods[i],&mi,sizeof(mi));
        auto base = (BYTE*)mi.lpBaseOfDll;
        // varredura de EAT/IAT prólogo: procura por JMP para fora dos limites
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.Size==0) continue;
        auto exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
        auto names = (DWORD*)(base + exp->AddressOfNames);
        for (DWORD j=0;j<exp->NumberOfNames;++j) {
            auto fn = (char*)(base + names[j]);
            FARPROC addr = GetProcAddress(mods[i],fn);
            // inline patch detection: primeiro byte não é 0xE9/0xE8?
            if (addr && (((BYTE*)addr)[0] != 0xE9 && ((BYTE*)addr)[0] != 0xE8)) {
                // presumivelmente sem hook, continua
            } else {
                return true;
            }
        }
    }
    return false;
}

// ————— IDT integrity check —————

bool AntiDebug::detectIDTIntegrity() {
    // loda IDTR
    struct { WORD limit; DWORD_PTR base; } idtr;
    __sidt(&idtr);
    // calcula checksum de primeiros 0x100 entradas
    BYTE* entries = (BYTE*)idtr.base;
    DWORD sum = 0;
    for (size_t i=0;i<0x100*16;i+=16) {
        DWORD low = *(DWORD*)(entries + i);
        DWORD high = *(DWORD*)(entries + i + 8);
        sum ^= (low ^ high);
    }
    return sum != 0;  // se alterado pelo debugger/VM
}

// ————— Evasão & patching —————

void AntiDebug::hideFromDebugger() {
    // NtSetInformationThread(ThreadHideFromDebugger)
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn    = (decltype(&NtQIP))GetProcAddress(ntdll,"NtSetInformationThread");
    if (fn) fn(GetCurrentThread(),0x11,nullptr,0);
}

void AntiDebug::patchDebuggerAPIs() {
    patchAPI("kernel32.dll","IsDebuggerPresent");
    patchAPI("kernel32.dll","CheckRemoteDebuggerPresent");
    patchAPI("ntdll.dll",   "NtQueryInformationProcess");
}

void AntiDebug::disableDebugPrivileges() {
    adjustPrivilege(SE_DEBUG_NAME,false);
}

void AntiDebug::patchAPI(const char* mod, const char* func) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) return;
    FARPROC f = GetProcAddress(h, func);
    if (!f) return;
    DWORD old;
    VirtualProtect(f, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE ret = 0xC3;                       // RET
    memcpy(f, &ret, 1);
    VirtualProtect(f, 5, old, &old);
}

bool AntiDebug::adjustPrivilege(const wchar_t* priv, bool enable) {
    HANDLE tk; TOKEN_PRIVILEGES tp; LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tk)) return false;
    if (!LookupPrivilegeValueW(nullptr,priv,&luid)) { CloseHandle(tk); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable?SE_PRIVILEGE_ENABLED:0;
    AdjustTokenPrivileges(tk,false,&tp,sizeof(tp),nullptr,nullptr);
    CloseHandle(tk);
    return GetLastError()==ERROR_SUCCESS;
}

} // namespace rgs::sdk::protection
