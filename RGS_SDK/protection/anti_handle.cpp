#include "anti_handle.hpp"
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <string>

// NtQuerySystemInformation
using NtQSI = NTSTATUS (WINAPI*)(ULONG, PVOID, ULONG, PULONG);

// SystemInformationClass
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

// Estruturas (não documentadas oficialmente) para consulta de handles
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT  UniqueProcessId;
    USHORT  CreatorBackTraceIndex;
    UCHAR   ObjectTypeIndex;
    UCHAR   HandleAttributes;
    USHORT  HandleValue;
    PVOID   Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

namespace rgs::sdk::protection {

AntiHandle::AntiHandle() = default;
AntiHandle::~AntiHandle() { shutdown(); }

bool AntiHandle::initialize() {
    initialized_ = true;
    return true;
}

void AntiHandle::shutdown() {
    stop_monitor();
    initialized_ = false;
    events_.clear();
}

void AntiHandle::set_enable_monitor(bool enable) { monitor_enabled_ = enable; }
void AntiHandle::set_poll_interval_ms(DWORD ms)  { poll_interval_ms_ = ms; }

bool AntiHandle::start_monitor() {
    if (!initialized_ || !monitor_enabled_) return false;
    if (monitor_running_) return true;
    monitor_running_ = true;
    monitor_thread_ = std::thread(&AntiHandle::monitor_loop, this);
    return true;
}

void AntiHandle::stop_monitor() {
    if (!monitor_running_) return;
    monitor_running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

std::vector<HandleDetection> AntiHandle::last_events() const {
    return events_;
}

std::vector<HandleDetection> AntiHandle::scan_once() {
    return enumerate_system_handles();
}

bool AntiHandle::detect_suspicious_handles() {
    auto res = scan_once();
    bool any = std::any_of(res.begin(), res.end(), [](const HandleDetection& d){ return d.isSuspicious; });
    if (any) {
        events_.insert(events_.end(), res.begin(), res.end());
    }
    return any;
}

bool AntiHandle::close_handle(HANDLE h) {
    // Melhor esforço: CloseHandle no contexto atual (não fecha handle de outro processo).
    // Para fechar handle de outro processo, seria necessário driver/kernel ou duplicação através de NtDuplicateObject
    // com permissões adequadas.
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    return CloseHandle(h) != 0;
}

void AntiHandle::close_all_suspicious() {
    for (const auto& e : events_) {
        if (e.isSuspicious && e.handle) {
            CloseHandle(e.handle);
        }
    }
}

std::vector<HandleDetection> AntiHandle::enumerate_system_handles() {
    std::vector<HandleDetection> out;

    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQuerySystemInformation = reinterpret_cast<NtQSI>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return out;

    ULONG len = 0x10000;
    std::vector<BYTE> buffer(len);

    NTSTATUS st = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), len, &len);
    if (st == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/ ) {
        buffer.resize(len);
        st = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), len, &len);
    }
    if (st != 0) return out;

    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
    DWORD myPid = GetCurrentProcessId();

    for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
        const auto& h = info->Handles[i];

        // Filtra apenas handles para o nosso processo: ObjectTypeIndex não é confiável entre versões.
        // Estratégia: tenta duplicar o handle para nosso processo e consulta se é um PROCESS handle.
        HANDLE ownerProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, h.UniqueProcessId);
        if (!ownerProc) continue;

        HANDLE dupHandle = nullptr;
        BOOL dupOk = DuplicateHandle(ownerProc, (HANDLE)(uintptr_t)h.HandleValue,
                                     GetCurrentProcess(), &dupHandle,
                                     0, FALSE, DUPLICATE_SAME_ACCESS);

        CloseHandle(ownerProc);
        if (!dupOk || !dupHandle) continue;

        // Consulta se dupHandle é de tipo PROCESS e se aponta para nosso PID
        DWORD targetPid = 0;
        DWORD retLen = 0;
        BOOL isProcessHandle = GetProcessIdOfThread(dupHandle) == 0; // se retorna 0, provavelmente não é thread
        // Tenta como processo
        targetPid = GetProcessId(dupHandle);

        if (isProcessHandle && targetPid == myPid) {
            // É um handle para nosso processo
            ACCESS_MASK access = h.GrantedAccess;
            bool susp = is_suspicious_access(access);
            std::string reason = access_to_string(access);
            std::string ownerExe = pid_to_exe(h.UniqueProcessId);

            HandleDetection det;
            det.ownerPid    = h.UniqueProcessId;
            det.ownerExe    = ownerExe;
            det.handle      = dupHandle;       // handle duplicado no nosso processo (podemos fechar)
            det.access      = access;
            det.isSuspicious= susp;
            det.reason      = susp ? ("Acesso suspeito: " + reason) : ("Acesso: " + reason);

            out.push_back(det);

            // Se não quiser manter o handle duplicado, feche já (mas então não será possível close_all_suspicious)
            // CloseHandle(dupHandle);
        } else {
            // Não é processo ou não aponta para nosso PID — fecha handle duplicado
            CloseHandle(dupHandle);
        }
    }

    return out;
}

bool AntiHandle::is_suspicious_access(ACCESS_MASK access) const {
    // Heurística: flags perigosas para o processo
    const ACCESS_MASK dangerous =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE |
        PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
        PROCESS_ALL_ACCESS;

    return (access & dangerous) != 0;
}

std::string AntiHandle::access_to_string(ACCESS_MASK access) const {
    std::string s;
    auto add = [&](const char* name, ACCESS_MASK mask) {
        if (access & mask) {
            if (!s.empty()) s += "|";
            s += name;
        }
    };
    add("VM_READ",    PROCESS_VM_READ);
    add("VM_WRITE",   PROCESS_VM_WRITE);
    add("VM_OP",      PROCESS_VM_OPERATION);
    add("QUERY",      PROCESS_QUERY_INFORMATION);
    add("QUERY_LIM",  PROCESS_QUERY_LIMITED_INFORMATION);
    add("SUSPEND",    PROCESS_SUSPEND_RESUME);
    add("DUP",        PROCESS_DUP_HANDLE);
    add("TERM",       PROCESS_TERMINATE);
    add("CREATE_TH",  PROCESS_CREATE_THREAD);
    add("ALL",        PROCESS_ALL_ACCESS);

    if (s.empty()) s = "NONE";
    return s;
}

std::string AntiHandle::pid_to_exe(DWORD pid) const {
    std::string name = "";

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return name;

    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                name = pe.szExeFile;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return name;
}

// Monitor

void AntiHandle::monitor_loop() {
    while (monitor_running_) {
        auto res = enumerate_system_handles();
        // Armazena apenas suspeitos para reduzir ruído
        for (auto& d : res) {
            if (d.isSuspicious) {
                events_.push_back(d);
            } else {
                // Fechar handles não suspeitos duplicados para evitar vazamento
                if (d.handle) CloseHandle(d.handle);
            }
        }
        Sleep(poll_interval_ms_);
    }
}

} // namespace rgs::sdk::protection
