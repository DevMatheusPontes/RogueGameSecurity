#pragma once

#include <windows.h>
#include <string>
#include <atomic>
#include <thread>

namespace rgs::sdk::protection {

class AntiAttach {
public:
    AntiAttach();
    ~AntiAttach();

    // Inicialização / encerramento
    bool initialize();
    void shutdown();

    // Ativa proteção de anti-attach (aplica todas as políticas)
    bool enable_protection();
    // Desativa políticas reversíveis (nem todas são 100% revertíveis em user-mode)
    void disable_protection();

    // Estado
    bool is_enabled() const;

    // Configuração
    void set_patch_apis(bool enable);
    void set_install_veh(bool enable);
    void set_disable_se_debug(bool enable);
    void set_break_on_termination(bool enable);

private:
    // Aplicadores
    bool apply_process_debug_flags_no_inherit();     // NtSetInformationProcess(ProcessDebugFlags = NoDebugInherit)
    bool apply_hide_threads_from_debugger();         // NtSetInformationThread(ThreadHideFromDebugger)
    bool close_process_debug_object();               // NtSetInformationProcess(ProcessDebugObjectHandle)
    bool apply_break_on_termination();               // NtSetInformationProcess(ProcessBreakOnTermination)
    bool drop_se_debug_privilege();                  // Remove SE_DEBUG_NAME do token
    bool patch_attach_related_apis();                // Patch IsDebuggerPresent, CheckRemoteDebuggerPresent, DbgUiConnectToDbg, etc.

    // VEH/SEH de dissuasão
    bool install_veh();
    void uninstall_veh();

    // Monitor re-aplica políticas periodicamente (anti-tamper)
    void start_monitor();
    void stop_monitor();
    void monitor_loop();

    // Helpers
    bool nt_set_information_process(ULONG clazz, PVOID info, ULONG len);
    bool nt_set_information_thread(HANDLE thread, ULONG clazz, PVOID info, ULONG len);
    bool patch_api(const char* module, const char* func);
    bool adjust_privilege(const wchar_t* priv, bool enable);

private:
    std::atomic<bool> enabled_{false};
    std::atomic<bool> patch_apis_{true};
    std::atomic<bool> install_veh_{true};
    std::atomic<bool> disable_se_debug_{true};
    std::atomic<bool> break_on_termination_{false};

    PVOID veh_handle_{nullptr};
    std::atomic<bool> monitor_running_{false};
    std::thread monitor_thread_;
};

} // namespace rgs::sdk::protection
