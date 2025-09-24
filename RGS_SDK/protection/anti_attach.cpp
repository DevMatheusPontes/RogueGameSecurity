#include "anti_attach.hpp"
#include <winternl.h>
#include <psapi.h>
#include <chrono>
#include <vector>
#include <algorithm>
#include <cstring>

// Declarações nativas
using NtSetInformationProcess_t = NTSTATUS (WINAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtSetInformationThread_t  = NTSTATUS (WINAPI*)(HANDLE, ULONG, PVOID, ULONG);

// Classes nativas usadas
static constexpr ULONG ProcessDebugFlags            = 0x1F; // NoDebugInherit quando valor = 1
static constexpr ULONG ProcessDebugObjectHandle     = 0x1E;
static constexpr ULONG ProcessBreakOnTermination    = 0x1D;
static constexpr ULONG ThreadHideFromDebugger       = 0x11;

namespace rgs::sdk::protection {

static LONG CALLBACK AntiAttachVectoredHandler(PEXCEPTION_POINTERS info) {
    // Dissuasão: em contexto de depuração/attach, força exceções ou manipula para quebrar fluxo do debugger
    // Exemplo: se houver breakpoint software (INT3), converte em EXCEPTION_CONTINUE_EXECUTION ou interrompe
    if (info && info->ExceptionRecord) {
        auto code = info->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
            // Em ambientes com attach, muitos debuggers injetam breakpoints ao entrar.
            // Aqui podemos mascarar e continuar, reduzindo utilidade do attach.
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

AntiAttach::AntiAttach()  = default;
AntiAttach::~AntiAttach() { shutdown(); }

bool AntiAttach::initialize() {
    // Não liga proteção automaticamente; deixa a cargo de enable_protection
    return true;
}

void AntiAttach::shutdown() {
    disable_protection();
}

bool AntiAttach::enable_protection() {
    bool ok = true;

    // 1) Bloqueia herança de depuração (no-debug inherit)
    ok &= apply_process_debug_flags_no_inherit();

    // 2) Esconde threads de debugger
    ok &= apply_hide_threads_from_debugger();

    // 3) Fecha debug object se houver
    ok &= close_process_debug_object();

    // 4) Opcional: quebra ao terminar (útil para impedir certos padrões de attach em runtime)
    if (break_on_termination_) ok &= apply_break_on_termination();

    // 5) Remove privilégio SE_DEBUG_NAME
    if (disable_se_debug_) ok &= drop_se_debug_privilege();

    // 6) Patch de APIs comuns de attach
    if (patch_apis_) ok &= patch_attach_related_apis();

    // 7) Instala VEH para atrapalhar attach
    if (install_veh_) ok &= install_veh();

    // 8) Monitor anti-tamper
    start_monitor();

    enabled_ = ok;
    return ok;
}

void AntiAttach::disable_protection() {
    stop_monitor();
    uninstall_veh();

    // Tentativa de reversão mínima:
    // - Privilégios removidos não são reabilitados automaticamente (política de segurança).
    // - Patches de API são permanentes no processo (podem ser reescritos pela aplicação se necessário).
    enabled_ = false;
}

bool AntiAttach::is_enabled() const {
    return enabled_.load();
}

void AntiAttach::set_patch_apis(bool enable) {
    patch_apis_ = enable;
}

void AntiAttach::set_install_veh(bool enable) {
    install_veh_ = enable;
}

void AntiAttach::set_disable_se_debug(bool enable) {
    disable_se_debug_ = enable;
}

void AntiAttach::set_break_on_termination(bool enable) {
    break_on_termination_ = enable;
}

// ————————————————————————— Aplicadores —————————————————————————

bool AntiAttach::apply_process_debug_flags_no_inherit() {
    // NoDebugInherit: valor 1 desabilita a herança de depuração
    ULONG flags = 1;
    return nt_set_information_process(ProcessDebugFlags, &flags, sizeof(flags));
}

bool AntiAttach::apply_hide_threads_from_debugger() {
    // Percorre threads do processo e oculta cada uma do debugger (assim bloqueia estratégias de attach por thread)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{ sizeof(te) };
    DWORD pid = GetCurrentProcessId();
    bool ok_any = false;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;
            ok_any |= nt_set_information_thread(th, ThreadHideFromDebugger, nullptr, 0);
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return ok_any;
}

bool AntiAttach::close_process_debug_object() {
    // Fecha o DebugObject se presente (impede attach persistente)
    // No user-mode, usamos NtSetInformationProcess(ProcessDebugObjectHandle, NULL)
    return nt_set_information_process(ProcessDebugObjectHandle, nullptr, 0);
}

bool AntiAttach::apply_break_on_termination() {
    // Ativa quebra ao terminar: alguns debuggers falham ao manter sessão com esse flag
    ULONG enable = 1;
    return nt_set_information_process(ProcessBreakOnTermination, &enable, sizeof(enable));
}

bool AntiAttach::drop_se_debug_privilege() {
    return adjust_privilege(SE_DEBUG_NAME, false);
}

bool AntiAttach::patch_attach_related_apis() {
    bool ok = true;
    // Kernel32: IsDebuggerPresent / CheckRemoteDebuggerPresent
    ok &= patch_api("kernel32.dll", "IsDebuggerPresent");
    ok &= patch_api("kernel32.dll", "CheckRemoteDebuggerPresent");
    // Ntdll: NtQueryInformationProcess (muito usado para attach/estado de debug)
    ok &= patch_api("ntdll.dll", "NtQueryInformationProcess");
    // DbgUiConnectToDbg / DbgUiRemoteBreakin (fluxos de UI de debug do ntdll/dbghelp)
    ok &= patch_api("ntdll.dll", "DbgUiConnectToDbg");
    ok &= patch_api("ntdll.dll", "DbgUiRemoteBreakin");
    return ok;
}

// ————————————————————————— VEH / SEH —————————————————————————

bool AntiAttach::install_veh() {
    if (veh_handle_) return true;
    veh_handle_ = AddVectoredExceptionHandler(1, AntiAttachVectoredHandler);
    return veh_handle_ != nullptr;
}

void AntiAttach::uninstall_veh() {
    if (veh_handle_) {
        RemoveVectoredExceptionHandler(veh_handle_);
        veh_handle_ = nullptr;
    }
}

// ————————————————————————— Monitor anti-tamper —————————————————————————

void AntiAttach::start_monitor() {
    if (monitor_running_) return;
    monitor_running_ = true;
    monitor_thread_ = std::thread(&AntiAttach::monitor_loop, this);
}

void AntiAttach::stop_monitor() {
    if (!monitor_running_) return;
    monitor_running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

void AntiAttach::monitor_loop() {
    // Reaplica periodicamente políticas sensíveis a tampering
    while (monitor_running_) {
        // Reforça NoDebugInherit
        apply_process_debug_flags_no_inherit();
        // Reforça ocultação de threads (novas threads)
        apply_hide_threads_from_debugger();
        // Fecha debug object se reaparecer
        close_process_debug_object();

        // Opcional: re-patch APIs (se algum módulo reescreveu)
        if (patch_apis_) {
            patch_attach_related_apis();
        }

        // Aguardar
        std::this_thread::sleep_for(std::chrono::milliseconds(750));
    }
}

// ————————————————————————— Helpers nativos / patch / privilégio —————————————————————————

bool AntiAttach::nt_set_information_process(ULONG clazz, PVOID info, ULONG len) {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto fn = reinterpret_cast<NtSetInformationProcess_t>(GetProcAddress(ntdll, "NtSetInformationProcess"));
    if (!fn) return false;
    NTSTATUS st = fn(GetCurrentProcess(), clazz, info, len);
    return st == 0;
}

bool AntiAttach::nt_set_information_thread(HANDLE thread, ULONG clazz, PVOID info, ULONG len) {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto fn = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
    if (!fn) return false;
    NTSTATUS st = fn(thread, clazz, info, len);
    return st == 0;
}

bool AntiAttach::patch_api(const char* module, const char* func) {
    HMODULE h = GetModuleHandleA(module);
    if (!h) return false;
    FARPROC f = GetProcAddress(h, func);
    if (!f) return false;

    DWORD oldProt = 0;
    if (!VirtualProtect((LPVOID)f, 8, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    // Escreve um 'ret' (0xC3). Para funções stdcall, isso retorna imediatamente com sucesso presumido.
    BYTE ret = 0xC3;
    std::memcpy((void*)f, &ret, 1);
    VirtualProtect((LPVOID)f, 8, oldProt, &oldProt);
    return true;
}

bool AntiAttach::adjust_privilege(const wchar_t* priv, bool enable) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) { CloseHandle(token); return false; }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    return err == ERROR_SUCCESS;
}

} // namespace rgs::sdk::protection
