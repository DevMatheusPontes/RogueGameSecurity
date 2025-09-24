#include "event_interceptor.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <detours.h> // biblioteca de hooking (Microsoft Detours ou similar)

#pragma comment(lib, "detours.lib")

namespace rgs::sdk::protection {

using pOpenProcess = HANDLE (WINAPI*)(DWORD, BOOL, DWORD);
using pWriteProcessMemory = BOOL (WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using pReadProcessMemory  = BOOL (WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
using pCreateRemoteThread = HANDLE (WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

static pOpenProcess origOpenProcess = OpenProcess;
static pWriteProcessMemory origWriteProcessMemory = WriteProcessMemory;
static pReadProcessMemory  origReadProcessMemory  = ReadProcessMemory;
static pCreateRemoteThread origCreateRemoteThread = CreateRemoteThread;

EventInterceptor::EventInterceptor() = default;
EventInterceptor::~EventInterceptor() { shutdown(); }

bool EventInterceptor::initialize() {
    if (initialized_) return true;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)origOpenProcess, hkOpenProcess);
    DetourAttach(&(PVOID&)origWriteProcessMemory, hkWriteProcessMemory);
    DetourAttach(&(PVOID&)origReadProcessMemory, hkReadProcessMemory);
    DetourAttach(&(PVOID&)origCreateRemoteThread, hkCreateRemoteThread);

    DetourTransactionCommit();

    initialized_ = true;
    return true;
}

void EventInterceptor::shutdown() {
    if (!initialized_) return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)origOpenProcess, hkOpenProcess);
    DetourDetach(&(PVOID&)origWriteProcessMemory, hkWriteProcessMemory);
    DetourDetach(&(PVOID&)origReadProcessMemory, hkReadProcessMemory);
    DetourDetach(&(PVOID&)origCreateRemoteThread, hkCreateRemoteThread);

    DetourTransactionCommit();

    initialized_ = false;
}

void EventInterceptor::add_whitelist(DWORD pid) { whitelist_.insert(pid); }
void EventInterceptor::remove_whitelist(DWORD pid) { whitelist_.erase(pid); }
void EventInterceptor::clear_whitelist() { whitelist_.clear(); }
void EventInterceptor::set_block_mode(bool enabled) { blockMode_ = enabled; }

std::vector<InterceptEvent> EventInterceptor::last_events() const { return eventos_; }

DWORD EventInterceptor::get_pid_from_handle(HANDLE hProc) {
    DWORD pid = 0;
    GetProcessId(hProc, &pid);
    return pid;
}

void EventInterceptor::log_event(const InterceptEvent& ev) {
    eventos_.push_back(ev);
}

// ———————————————— Hooks ————————————————

HANDLE WINAPI EventInterceptor::hkOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    DWORD caller = GetCurrentProcessId();
    bool allowed = whitelist_.count(pid) > 0 || pid == caller;

    InterceptEvent ev{ "OpenProcess", caller, pid, "Tentativa de abrir processo", !allowed && blockMode_ };
    log_event(ev);

    if (!allowed && blockMode_) {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return origOpenProcess(access, inherit, pid);
}

BOOL WINAPI EventInterceptor::hkWriteProcessMemory(HANDLE hProc, LPVOID base, LPCVOID buf, SIZE_T sz, SIZE_T* written) {
    DWORD caller = GetCurrentProcessId();
    DWORD target = get_pid_from_handle(hProc);
    bool allowed = whitelist_.count(target) > 0 || target == caller;

    InterceptEvent ev{ "WriteProcessMemory", caller, target, "Tentativa de escrever memória remota", !allowed && blockMode_ };
    log_event(ev);

    if (!allowed && blockMode_) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return origWriteProcessMemory(hProc, base, buf, sz, written);
}

BOOL WINAPI EventInterceptor::hkReadProcessMemory(HANDLE hProc, LPCVOID base, LPVOID buf, SIZE_T sz, SIZE_T* read) {
    DWORD caller = GetCurrentProcessId();
    DWORD target = get_pid_from_handle(hProc);
    bool allowed = whitelist_.count(target) > 0 || target == caller;

    InterceptEvent ev{ "ReadProcessMemory", caller, target, "Tentativa de ler memória remota", !allowed && blockMode_ };
    log_event(ev);

    if (!allowed && blockMode_) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return origReadProcessMemory(hProc, base, buf, sz, read);
}

HANDLE WINAPI EventInterceptor::hkCreateRemoteThread(HANDLE hProc, LPSECURITY_ATTRIBUTES sa, SIZE_T st, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid) {
    DWORD caller = GetCurrentProcessId();
    DWORD target = get_pid_from_handle(hProc);
    bool allowed = whitelist_.count(target) > 0 || target == caller;

    InterceptEvent ev{ "CreateRemoteThread", caller, target, "Tentativa de criar thread remota", !allowed && blockMode_ };
    log_event(ev);

    if (!allowed && blockMode_) {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return origCreateRemoteThread(hProc, sa, st, start, param, flags, tid);
}

} // namespace rgs::sdk::protection
