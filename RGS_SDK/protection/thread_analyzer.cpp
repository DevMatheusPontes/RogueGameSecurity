#include "thread_analyzer.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <algorithm>

namespace rgs::sdk::protection {

// NtQueryInformationThread
using NtQIT = NTSTATUS (WINAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

ThreadAnalyzer::ThreadAnalyzer() = default;
ThreadAnalyzer::~ThreadAnalyzer() { shutdown(); }

bool ThreadAnalyzer::initialize() {
    initialized_ = true;
    return true;
}

void ThreadAnalyzer::shutdown() {
    initialized_ = false;
    events_.clear();
}

uintptr_t ThreadAnalyzer::get_thread_start(HANDLE hThread) {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn = reinterpret_cast<NtQIT>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    if (!fn) return 0;

    PVOID start = nullptr;
    NTSTATUS st = fn(hThread, (THREADINFOCLASS)9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
    if (st == 0) return reinterpret_cast<uintptr_t>(start);
    return 0;
}

std::string ThreadAnalyzer::module_from_address(uintptr_t addr) {
    HMODULE mods[1024]; DWORD needed;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return "";
    size_t count = needed / sizeof(HMODULE);

    for (size_t i=0;i<count;i++) {
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
            uintptr_t base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            size_t size    = mi.SizeOfImage;
            if (addr >= base && addr < base+size) {
                char path[MAX_PATH]{};
                GetModuleFileNameA(mods[i], path, sizeof(path));
                return path;
            }
        }
    }
    return "";
}

bool ThreadAnalyzer::is_address_in_module(uintptr_t addr, std::string& modName) {
    modName = module_from_address(addr);
    return !modName.empty();
}

std::vector<ThreadDetection> ThreadAnalyzer::scan_threads() {
    std::vector<ThreadDetection> out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te{ sizeof(te) };
    DWORD pid = GetCurrentProcessId();

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;

            uintptr_t start = get_thread_start(th);
            CloseHandle(th);

            std::string mod;
            bool inModule = is_address_in_module(start, mod);

            ThreadDetection det;
            det.tid          = te.th32ThreadID;
            det.startAddress = start;
            det.module       = mod;
            det.isSuspicious = !inModule;
            det.reason       = inModule ? "Thread legítima" : "StartAddress fora de módulos conhecidos";

            out.push_back(det);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    events_ = out;
    return out;
}

bool ThreadAnalyzer::detect_suspicious_threads() {
    auto res = scan_threads();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

std::vector<ThreadDetection> ThreadAnalyzer::last_events() const {
    return events_;
}

bool ThreadAnalyzer::suspend_thread(DWORD tid) {
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) return false;
    DWORD r = SuspendThread(th);
    CloseHandle(th);
    return r != (DWORD)-1;
}

bool ThreadAnalyzer::terminate_thread(DWORD tid) {
    HANDLE th = OpenThread(THREAD_TERMINATE, FALSE, tid);
    if (!th) return false;
    BOOL ok = TerminateThread(th, 0);
    CloseHandle(th);
    return ok != 0;
}

} // namespace rgs::sdk::protection
