#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <unordered_set>

namespace rgs::sdk::protection {

struct InterceptEvent {
    std::string api;
    DWORD       callerPid;
    DWORD       targetPid;
    std::string descricao;
    bool        bloqueado;
};

class EventInterceptor {
public:
    EventInterceptor();
    ~EventInterceptor();

    bool initialize();
    void shutdown();

    // Configuração
    void add_whitelist(DWORD pid);
    void remove_whitelist(DWORD pid);
    void clear_whitelist();

    void set_block_mode(bool enabled);

    // Últimos eventos
    std::vector<InterceptEvent> last_events() const;

private:
    // Hooks internos
    static HANDLE WINAPI hkOpenProcess(DWORD access, BOOL inherit, DWORD pid);
    static BOOL   WINAPI hkWriteProcessMemory(HANDLE hProc, LPVOID base, LPCVOID buf, SIZE_T sz, SIZE_T* written);
    static BOOL   WINAPI hkReadProcessMemory(HANDLE hProc, LPCVOID base, LPVOID buf, SIZE_T sz, SIZE_T* read);
    static HANDLE WINAPI hkCreateRemoteThread(HANDLE hProc, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    // Helpers
    static DWORD get_pid_from_handle(HANDLE hProc);
    static void log_event(const InterceptEvent& ev);

private:
    static inline std::unordered_set<DWORD> whitelist_;
    static inline std::vector<InterceptEvent> eventos_;
    static inline std::atomic<bool> blockMode_{true};
    static inline bool initialized_{false};
};

} // namespace rgs::sdk::protection
