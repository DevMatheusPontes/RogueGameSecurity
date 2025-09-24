#include "interface_protection.hpp"

#include <tlhelp32.h>
#include <psapi.h>
#include <dwmapi.h>
#include <algorithm>

#pragma comment(lib, "dwmapi.lib")

namespace rgs::sdk::protection {

InterfaceProtection::InterfaceProtection() = default;
InterfaceProtection::~InterfaceProtection() { shutdown(); }

bool InterfaceProtection::initialize() {
    initialized_ = true;
    return true;
}

void InterfaceProtection::shutdown() {
    initialized_ = false;
    eventos_.clear();
}

std::vector<InterfaceThreat> InterfaceProtection::last_events() const {
    return eventos_;
}

// ————————————————————————— Varreduras —————————————————————————

std::vector<InterfaceThreat> InterfaceProtection::scan_windows_attributes() {
    eventos_.clear();
    EnumWindows(enum_windows_proc, reinterpret_cast<LPARAM>(this));
    return eventos_;
}

std::vector<InterfaceThreat> InterfaceProtection::scan_overlay_modules() {
    std::vector<InterfaceThreat> out;

    // Procura módulos conhecidos de overlay/stream/record (lista expandível)
    // OBS, NVIDIA Share, Discord Overlay, RTSS, Steam Overlay
    static const std::vector<std::string> suspects = {
        "obs.dll", "obs32.dll", "obs64.dll",
        "graphics-hook.dll", "libobs.dll",
        "nvspcap.dll", "nvspcap64.dll", "nvosd.dll",
        "discordhook.dll", "discordhook64.dll",
        "RTSSHooks.dll", "RTSSHooks64.dll", "RTSS.exe",
        "gameoverlayrenderer.dll", "gameoverlayui.exe"
    };

    // Enumera processos
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            auto mods = list_process_modules(pid);
            for (auto& m : mods) {
                std::string low = m;
                std::transform(low.begin(), low.end(), low.begin(), ::tolower);
                for (auto& s : suspects) {
                    std::string sl = s;
                    std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
                    if (low.find(sl) != std::string::npos) {
                        InterfaceThreat t{};
                        t.hwnd = nullptr;
                        t.pid = pid;
                        t.classe = "";
                        t.titulo = pe.szExeFile;
                        t.tipo = "OverlayModule";
                        t.descricao = "Módulo de overlay/stream encontrado: " + m;
                        t.suspeito = true;
                        out.push_back(t);
                    }
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    // Merge com eventos
    eventos_.insert(eventos_.end(), out.begin(), out.end());
    return out;
}

std::vector<InterfaceThreat> InterfaceProtection::scan_all() {
    std::vector<InterfaceThreat> out;
    auto w = scan_windows_attributes();
    out.insert(out.end(), w.begin(), w.end());
    auto m = scan_overlay_modules();
    out.insert(out.end(), m.begin(), m.end());
    eventos_ = out;
    return out;
}

bool InterfaceProtection::detect_streamproof() {
    auto all = scan_all();
    return std::any_of(all.begin(), all.end(), [](const InterfaceThreat& t){ return t.suspeito; });
}

// ————————————————————————— Correções —————————————————————————

bool InterfaceProtection::remove_exclude_from_capture(HWND hwnd) {
    // Remove WDA_EXCLUDEFROMCAPTURE (anti-streamproof)
    DWORD current{};
    if (!get_window_affinity(hwnd, current)) return false;
    if (current == WDA_EXCLUDEFROMCAPTURE || current == WDA_MONITOR) {
        return set_window_affinity(hwnd, WDA_NONE);
    }
    return true; // já não está excluída
}

bool InterfaceProtection::uncloak_window(HWND hwnd) {
    // Remove "cloaking" (janela ocultada pelo DWM) quando possível
    BOOL cloaked = FALSE;
    if (SUCCEEDED(DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked)))) {
        if (cloaked) {
            // Não há API pública para "descloaking"; tentativa: mostrar e forçar ativação
            ShowWindow(hwnd, SW_SHOW);
            SetWindowPos(hwnd, HWND_TOP, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);
            // Se ainda cloaked, apenas reportamos
        }
        return TRUE;
    }
    return FALSE;
}

bool InterfaceProtection::normalize_layered_window(HWND hwnd) {
    LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
    if (exStyle & WS_EX_LAYERED) {
        // Remove WS_EX_TRANSPARENT para evitar "pass-through"
        LONG newStyle = exStyle & ~WS_EX_TRANSPARENT;
        SetWindowLongA(hwnd, GWL_EXSTYLE, newStyle);

        // Ajusta alpha para 255 (totalmente visível)
        BYTE alpha = 255;
        COLORREF crKey = 0;
        DWORD flags = 0;
        if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
            SetLayeredWindowAttributes(hwnd, crKey, 255, flags | LWA_ALPHA);
        }
        return true;
    }
    return false;
}

void InterfaceProtection::enforce_capture_visibility() {
    // Aplica correções em todas janelas suspeitas marcadas como streamproof
    for (auto& t : eventos_) {
        if (!t.hwnd) continue;
        if (t.tipo == "ExclusionFromCapture") {
            remove_exclude_from_capture(t.hwnd);
        } else if (t.tipo == "LayeredTransparent") {
            normalize_layered_window(t.hwnd);
        } else if (t.tipo == "Cloaked") {
            uncloak_window(t.hwnd);
        }
    }
}

// ————————————————————————— Helpers —————————————————————————

BOOL CALLBACK InterfaceProtection::enum_windows_proc(HWND hwnd, LPARAM lParam) {
    auto self = reinterpret_cast<InterfaceProtection*>(lParam);

    // Ignora janelas inválidas ou de outros desktops
    if (!IsWindow(hwnd)) return TRUE;

    InterfaceThreat t{};
    t.hwnd = hwnd;
    t.pid = self->window_pid(hwnd);
    t.classe = self->window_class(hwnd);
    t.titulo = self->window_title(hwnd);
    t.suspeito = false;

    // 1) Verifica Display Affinity (excluir de captura)
    DWORD affinity{};
    if (self->get_window_affinity(hwnd, affinity)) {
        if (affinity == WDA_EXCLUDEFROMCAPTURE) {
            t.tipo = "ExclusionFromCapture";
            t.descricao = "Janela marcada como excluída da captura (anti-stream) via DisplayAffinity";
            t.suspeito = true;
            self->eventos_.push_back(t);
            // Continua análise para acumular múltiplos motivos
        }
    }

    // 2) Layered + Transparent (comportamento pass-through invisível à captura)
    if (self->is_layered_transparent(hwnd)) {
        InterfaceThreat lt = t;
        lt.tipo = "LayeredTransparent";
        lt.descricao = "Janela layered com transparência/pass-through (pode burlar captura)";
        lt.suspeito = true;
        self->eventos_.push_back(lt);
    }

    // 3) DWM cloaking
    if (self->is_cloaked(hwnd)) {
        InterfaceThreat ck = t;
        ck.tipo = "Cloaked";
        ck.descricao = "Janela cloaked pelo DWM (pode ocultar overlay em captura)";
        ck.suspeito = true;
        self->eventos_.push_back(ck);
    }

    return TRUE;
}

bool InterfaceProtection::get_window_affinity(HWND hwnd, DWORD& affinity) const {
    // GetWindowDisplayAffinity está em user32.dll (Win10+)
    typedef BOOL (WINAPI* GetWDA)(HWND, DWORD*);
    HMODULE hUser = GetModuleHandleA("user32.dll");
    if (!hUser) return false;
    auto fn = reinterpret_cast<GetWDA>(GetProcAddress(hUser, "GetWindowDisplayAffinity"));
    if (!fn) return false;
    return fn(hwnd, &affinity) != 0;
}

bool InterfaceProtection::set_window_affinity(HWND hwnd, DWORD affinity) const {
    typedef BOOL (WINAPI* SetWDA)(HWND, DWORD);
    HMODULE hUser = GetModuleHandleA("user32.dll");
    if (!hUser) return false;
    auto fn = reinterpret_cast<SetWDA>(GetProcAddress(hUser, "SetWindowDisplayAffinity"));
    if (!fn) return false;
    return fn(hwnd, affinity) != 0;
}

bool InterfaceProtection::is_layered_transparent(HWND hwnd) const {
    LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) != 0) {
        BYTE alpha = 255;
        COLORREF crKey = 0;
        DWORD flags = 0;
        if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
            // Transparência forte + TRANSPARENT sugere stream-proof pass-through
            if ((exStyle & WS_EX_TRANSPARENT) != 0) return true;
            if ((flags & LWA_ALPHA) && alpha < 60) return true; // quase invisível
        }
    }
    return false;
}

bool InterfaceProtection::is_cloaked(HWND hwnd) const {
    BOOL cloaked = FALSE;
    if (SUCCEEDED(DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked)))) {
        return cloaked != FALSE;
    }
    return false;
}

std::string InterfaceProtection::window_class(HWND hwnd) const {
    char cls[256]{};
    GetClassNameA(hwnd, cls, sizeof(cls));
    return std::string(cls);
}

std::string InterfaceProtection::window_title(HWND hwnd) const {
    char title[256]{};
    GetWindowTextA(hwnd, title, sizeof(title));
    return std::string(title);
}

DWORD InterfaceProtection::window_pid(HWND hwnd) const {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

std::vector<std::string> InterfaceProtection::list_process_modules(DWORD pid) const {
    std::vector<std::string> paths;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return paths;

    HMODULE mods[1024]; DWORD needed{};
    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            char path[MAX_PATH]{};
            if (GetModuleFileNameExA(hProc, mods[i], path, sizeof(path))) {
                paths.emplace_back(path);
            }
        }
    }
    CloseHandle(hProc);
    return paths;
}

bool InterfaceProtection::is_known_overlay_module(const std::string& path) const {
    // Já coberto em scan_overlay_modules(), função disponível para extensões futuras
    return false;
}

} // namespace rgs::sdk::protection
