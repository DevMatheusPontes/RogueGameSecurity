#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <thread>

namespace rgs::sdk::protection {

struct SpeedhackDetection {
    std::string method;
    std::string description;
    double      value;      // métrica associada (ex.: razão QPC/Tick)
    ULONGLONG   timestamp;  // GetTickCount64 no momento da detecção
    bool        isSuspicious;
};

class AntiSpeedHack {
public:
    AntiSpeedHack();
    ~AntiSpeedHack();

    // Inicialização / encerramento
    bool initialize();
    void shutdown();

    // Configuração
    void set_enable_monitor(bool enable);
    void set_sample_interval_ms(DWORD ms);
    void set_ratio_threshold_min(double v); // razão mínima aceitável QPC/Tick (ex.: ~0.9)
    void set_ratio_threshold_max(double v); // razão máxima aceitável QPC/Tick (ex.: ~1.1)
    void set_max_backward_ms(LONG ms);      // tolerância de retrocesso de system time
    void set_max_drift_ppm(double ppm);     // tolerância de drift em ppm entre QPC e Tick

    // Execução
    bool start_monitor();
    void stop_monitor();

    // Scans pontuais
    std::vector<SpeedhackDetection> scan_once();
    bool detect_speedhack();

    // Últimos eventos
    std::vector<SpeedhackDetection> last_events() const;

private:
    // Captura múltiplas fontes de tempo
    struct TimeSnapshot {
        ULONGLONG tick64;     // GetTickCount64
        DWORD     timeGet;    // timeGetTime
        LARGE_INTEGER qpc;    // QueryPerformanceCounter
        LARGE_INTEGER qpf;    // QueryPerformanceFrequency
        ULONGLONG fileTime;   // GetSystemTimeAsFileTime (100ns since 1601)
    };

    TimeSnapshot capture_time() const;

    // Verificações
    bool check_ratio_qpc_tick(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out);
    bool check_ratio_timeget_tick(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out);
    bool check_backward_system_time(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out);
    bool check_drift_ppm(const TimeSnapshot& base, const TimeSnapshot& cur, SpeedhackDetection& out);

    // Monitor loop
    void monitor_loop();

    // Helpers
    static ULONGLONG filetime_to_ms(ULONGLONG ft100ns);
    static double     delta_ms_qpc(const LARGE_INTEGER& qpf, const LARGE_INTEGER& prev, const LARGE_INTEGER& cur);
    static double     safe_ratio(double num, double den);

private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> monitor_enabled_{true};
    std::atomic<bool> monitor_running_{false};

    DWORD   sample_interval_ms_{250};
    double  ratio_min_{0.90};
    double  ratio_max_{1.10};
    LONG    max_backward_ms_{150};
    double  max_drift_ppm_{200.0}; // 200 ppm (~0.02%) tolerância

    std::thread monitor_thread_;
    TimeSnapshot base_{};
    std::vector<SpeedhackDetection> events_;
};

} // namespace rgs::sdk::protection
