#include "anti_speedhack.hpp"
#include <mmsystem.h>
#include <algorithm>

#pragma comment(lib, "winmm.lib")

namespace rgs::sdk::protection {

AntiSpeedHack::AntiSpeedHack() = default;
AntiSpeedHack::~AntiSpeedHack() { shutdown(); }

bool AntiSpeedHack::initialize() {
    base_ = capture_time();
    initialized_ = true;
    return true;
}

void AntiSpeedHack::shutdown() {
    stop_monitor();
    initialized_ = false;
    events_.clear();
}

void AntiSpeedHack::set_enable_monitor(bool enable) { monitor_enabled_ = enable; }
void AntiSpeedHack::set_sample_interval_ms(DWORD ms) { sample_interval_ms_ = ms; }
void AntiSpeedHack::set_ratio_threshold_min(double v) { ratio_min_ = v; }
void AntiSpeedHack::set_ratio_threshold_max(double v) { ratio_max_ = v; }
void AntiSpeedHack::set_max_backward_ms(LONG ms) { max_backward_ms_ = ms; }
void AntiSpeedHack::set_max_drift_ppm(double ppm) { max_drift_ppm_ = ppm; }

bool AntiSpeedHack::start_monitor() {
    if (!initialized_ || !monitor_enabled_) return false;
    if (monitor_running_) return true;
    monitor_running_ = true;
    monitor_thread_ = std::thread(&AntiSpeedHack::monitor_loop, this);
    return true;
}

void AntiSpeedHack::stop_monitor() {
    if (!monitor_running_) return;
    monitor_running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

std::vector<SpeedhackDetection> AntiSpeedHack::last_events() const {
    return events_;
}

std::vector<SpeedhackDetection> AntiSpeedHack::scan_once() {
    std::vector<SpeedhackDetection> out;

    TimeSnapshot prev = capture_time();
    Sleep(sample_interval_ms_);
    TimeSnapshot cur  = capture_time();

    SpeedhackDetection det{};
    if (check_ratio_qpc_tick(prev, cur, det)) out.push_back(det);
    if (check_ratio_timeget_tick(prev, cur, det)) out.push_back(det);
    if (check_backward_system_time(prev, cur, det)) out.push_back(det);
    if (check_drift_ppm(base_, cur, det)) out.push_back(det);

    return out;
}

bool AntiSpeedHack::detect_speedhack() {
    auto res = scan_once();
    auto any = std::any_of(res.begin(), res.end(), [](const SpeedhackDetection& d){ return d.isSuspicious; });
    if (any) {
        events_.insert(events_.end(), res.begin(), res.end());
    }
    return any;
}

AntiSpeedHack::TimeSnapshot AntiSpeedHack::capture_time() const {
    TimeSnapshot s{};
    s.tick64 = GetTickCount64();
    s.timeGet = timeGetTime();
    QueryPerformanceCounter(&s.qpc);
    QueryPerformanceFrequency(&s.qpf);

    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    s.fileTime = uli.QuadPart; // 100ns since 1601

    return s;
}

bool AntiSpeedHack::check_ratio_qpc_tick(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out) {
    double dqpc  = delta_ms_qpc(cur.qpf, prev.qpc, cur.qpc);
    double dtick = static_cast<double>(cur.tick64 - prev.tick64);
    double ratio = safe_ratio(dqpc, dtick);

    bool suspicious = (ratio < ratio_min_ || ratio > ratio_max_);
    out = {
        "QPC/Tick",
        "Razão entre QPC e GetTickCount64 fora do intervalo",
        ratio,
        cur.tick64,
        suspicious
    };
    return suspicious;
}

bool AntiSpeedHack::check_ratio_timeget_tick(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out) {
    double dtimeget = static_cast<double>(cur.timeGet - prev.timeGet);
    double dtick    = static_cast<double>(cur.tick64 - prev.tick64);
    double ratio    = safe_ratio(dtimeget, dtick);

    bool suspicious = (ratio < ratio_min_ || ratio > ratio_max_);
    out = {
        "timeGet/Tick",
        "Razão entre timeGetTime e GetTickCount64 fora do intervalo",
        ratio,
        cur.tick64,
        suspicious
    };
    return suspicious;
}

bool AntiSpeedHack::check_backward_system_time(const TimeSnapshot& prev, const TimeSnapshot& cur, SpeedhackDetection& out) {
    ULONGLONG prevMs = filetime_to_ms(prev.fileTime);
    ULONGLONG curMs  = filetime_to_ms(cur.fileTime);
    LONG delta = static_cast<LONG>(curMs - prevMs);

    bool suspicious = (delta < -max_backward_ms_);
    out = {
        "SystemTime.Backward",
        "Retrocesso do tempo de sistema acima do limite",
        static_cast<double>(delta),
        cur.tick64,
        suspicious
    };
    return suspicious;
}

bool AntiSpeedHack::check_drift_ppm(const TimeSnapshot& base, const TimeSnapshot& cur, SpeedhackDetection& out) {
    // Drift entre QPC (relativo) e Tick64 (relativo) desde a base
    double qpc_ms  = delta_ms_qpc(cur.qpf, base.qpc, cur.qpc);
    double tick_ms = static_cast<double>(cur.tick64 - base.tick64);

    double drift = (qpc_ms - tick_ms); // ms de diferença
    // ppm = (diferença / referência) * 1e6
    double ppm = safe_ratio(drift, tick_ms) * 1e6;

    bool suspicious = (std::abs(ppm) > max_drift_ppm_);
    out = {
        "QPC/Tick.DriftPPM",
        "Drift entre QPC e Tick excede tolerância (ppm)",
        ppm,
        cur.tick64,
        suspicious
    };
    return suspicious;
}

// —————————————————————————— Monitor ——————————————————————————

void AntiSpeedHack::monitor_loop() {
    // Janela móvel: avalia continuamente e armazena eventos suspeitos
    TimeSnapshot prev = capture_time();
    while (monitor_running_) {
        Sleep(sample_interval_ms_);
        TimeSnapshot cur = capture_time();

        SpeedhackDetection det{};
        if (check_ratio_qpc_tick(prev, cur, det)) events_.push_back(det);
        if (check_ratio_timeget_tick(prev, cur, det)) events_.push_back(det);
        if (check_backward_system_time(prev, cur, det)) events_.push_back(det);
        if (check_drift_ppm(base_, cur, det)) events_.push_back(det);

        prev = cur;
    }
}

// —————————————————————————— Helpers ——————————————————————————

ULONGLONG AntiSpeedHack::filetime_to_ms(ULONGLONG ft100ns) {
    // 100ns → ms
    return ft100ns / 10000ULL;
}

double AntiSpeedHack::delta_ms_qpc(const LARGE_INTEGER& qpf, const LARGE_INTEGER& prev, const LARGE_INTEGER& cur) {
    LONGLONG ticks = cur.QuadPart - prev.QuadPart;
    if (qpf.QuadPart == 0) return 0.0;
    return (static_cast<double>(ticks) * 1000.0) / static_cast<double>(qpf.QuadPart);
}

double AntiSpeedHack::safe_ratio(double num, double den) {
    if (den == 0.0) return 0.0;
    return num / den;
}

} // namespace rgs::sdk::protection
