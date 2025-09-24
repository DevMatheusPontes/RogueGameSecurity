#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

namespace rgs::sdk::protection {

// Constantes do Display Affinity (Win10/11)
#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
// Valor oficial é 0x00000011 em builds recentes (Win11+)
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// Atributos DWM (não expostos em headers antigos)
#ifndef DWMWA_CLOAK
#define DWMWA_CLOAK 13
#endif
#ifndef DWMWA_CLOAKED
#define DWMWA_CLOAKED 14
#endif

struct InterfaceThreat {
    HWND        hwnd;
    DWORD       pid;
    std::string classe;
    std::string titulo;
    std::string tipo;        // "ExclusionFromCapture", "LayeredTransparent", "Cloaked", "OverlayModule"
    std::string descricao;
    bool        suspeito;
};

class InterfaceProtection {
public:
    InterfaceProtection();
    ~InterfaceProtection();

    bool initialize();
    void shutdown();

    // Varreduras principais
    std::vector<InterfaceThreat> scan_windows_attributes(); // WDA, WS_EX_LAYERED/TRANSPARENT, DWM cloaking
    std::vector<InterfaceThreat> scan_overlay_modules();    // Módulos/overlays comuns (OBS/NVIDIA/Discord/RTSS)

    // Agregado
    std::vector<InterfaceThreat> scan_all();
    bool detect_streamproof();

    // Ações de correção (melhor esforço e seguras)
    bool remove_exclude_from_capture(HWND hwnd);  // SetWindowDisplayAffinity(WDA_NONE)
    bool uncloak_window(HWND hwnd);               // DWM: remove cloaking quando possível
    bool normalize_layered_window(HWND hwnd);     // Remove WS_EX_TRANSPARENT e alpha excessiva

    // Aplicação ampla (em todas janelas suspeitas encontradas)
    void enforce_capture_visibility();

    // Últimos eventos
    std::vector<InterfaceThreat> last_events() const;

private:
    // Helpers
    static BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM lParam);
    bool get_window_affinity(HWND hwnd, DWORD& affinity) const;
    bool set_window_affinity(HWND hwnd, DWORD affinity) const;
    bool is_layered_transparent(HWND hwnd) const;
    bool is_cloaked(HWND hwnd) const;

    std::string window_class(HWND hwnd) const;
    std::string window_title(HWND hwnd) const;
    DWORD window_pid(HWND hwnd) const;

    // Overlay modules scan
    std::vector<std::string> list_process_modules(DWORD pid) const;
    bool is_known_overlay_module(const std::string& path) const;

private:
    std::atomic<bool> initialized_{false};
    std::vector<InterfaceThreat> eventos_;
};

} // namespace rgs::sdk::protection
