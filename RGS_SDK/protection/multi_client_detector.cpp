#include "multi_client_detector.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

namespace rgs::sdk::protection {

MultiClientDetector::MultiClientDetector() = default;
MultiClientDetector::~MultiClientDetector() { shutdown(); }

bool MultiClientDetector::initialize(const std::wstring& mutexName, const std::wstring& windowTitle) {
    mutexName_ = mutexName;
    windowTitle_ = windowTitle;

    mutexHandle_ = CreateMutexW(nullptr, FALSE, mutexName_.c_str());
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Já existe outra instância
        return false;
    }

    initialized_ = true;
    return true;
}

void MultiClientDetector::shutdown() {
    if (mutexHandle_) {
        CloseHandle(mutexHandle_);
        mutexHandle_ = nullptr;
    }
    initialized_ = false;
    events_.clear();
}

std::vector<MultiClientDetection> MultiClientDetector::scan_processes() {
    std::vector<MultiClientDetection> out;
    DWORD myPid = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) continue;

            std::wstring exe(pe.szExeFile);
            std::wstring myExe;
            wchar_t path[MAX_PATH];
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            myExe = path;

            std::wstring exeLower = exe; std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::towlower);
            std::wstring myExeLower = myExe; std::transform(myExeLower.begin(), myExeLower.end(), myExeLower.begin(), ::towlower);

            if (exeLower.find(myExeLower.substr(myExeLower.find_last_of(L"\\") + 1)) != std::wstring::npos) {
                MultiClientDetection d;
                d.pid = pe.th32ProcessID;
                d.exeName = std::string(exe.begin(), exe.end());
                d.reason = "Outro processo do mesmo executável detectado";
                d.isSuspicious = true;
                out.push_back(d);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    events_.insert(events_.end(), out.begin(), out.end());
    return out;
}

std::vector<MultiClientDetection> MultiClientDetector::scan_windows() {
    std::vector<MultiClientDetection> out;

    HWND hwnd = FindWindowW(nullptr, windowTitle_.c_str());
    if (hwnd && hwnd != GetConsoleWindow()) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId()) {
            MultiClientDetection d;
            d.pid = pid;
            d.exeName = "Desconhecido";
            d.reason = "Outra janela com mesmo título detectada";
            d.isSuspicious = true;
            out.push_back(d);
        }
    }

    events_.insert(events_.end(), out.begin(), out.end());
    return out;
}

bool MultiClientDetector::detect_multiple_instances() {
    auto p = scan_processes();
    auto w = scan_windows();
    auto any = [](const std::vector<MultiClientDetection>& v){
        return std::any_of(v.begin(), v.end(), [](auto& d){ return d.isSuspicious; });
    };
    return any(p) || any(w);
}

std::vector<MultiClientDetection> MultiClientDetector::last_events() const {
    return events_;
}

void MultiClientDetector::enforce_single_instance() {
    if (detect_multiple_instances()) {
        // Fecha imediatamente o processo atual
        ExitProcess(0);
    }
}

} // namespace rgs::sdk::protection
