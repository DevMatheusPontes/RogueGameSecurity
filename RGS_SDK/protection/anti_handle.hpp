#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <thread>

namespace rgs::sdk::protection {

struct HandleDetection {
    DWORD   ownerPid;         // PID que possui o handle
    std::string ownerExe;     // Executável do processo dono do handle (melhor esforço)
    HANDLE  handle;           // Handle (pseudo handle no contexto do nosso processo)
    ACCESS_MASK access;       // Máscara de acesso
    bool    isSuspicious;     // Heurística de suspeita
    std::string reason;       // Motivo da suspeita
};

class AntiHandle {
public:
    AntiHandle();
    ~AntiHandle();

    // Inicialização / encerramento
    bool initialize();
    void shutdown();

    // Configuração
    void set_enable_monitor(bool enable);
    void set_poll_interval_ms(DWORD ms);

    // Execução
    bool start_monitor();
    void stop_monitor();

    // Varredura pontual
    std::vector<HandleDetection> scan_once();
    bool detect_suspicious_handles();

    // Últimos eventos
    std::vector<HandleDetection> last_events() const;

    // Resposta ativa (melhor esforço, pode falhar)
    bool close_handle(HANDLE h);
    void close_all_suspicious();

private:
    // Helpers
    std::vector<HandleDetection> enumerate_system_handles();
    bool is_suspicious_access(ACCESS_MASK access) const;
    std::string access_to_string(ACCESS_MASK access) const;
    std::string pid_to_exe(DWORD pid) const;

    // Monitor
    void monitor_loop();

private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> monitor_enabled_{true};
    std::atomic<bool> monitor_running_{false};

    DWORD poll_interval_ms_{750};
    std::thread monitor_thread_;

    std::vector<HandleDetection> events_;
};

} // namespace rgs::sdk::protection
