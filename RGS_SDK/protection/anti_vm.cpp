#include "anti_vm.hpp"
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <shlwapi.h>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace rgs::sdk::protection {

AntiVM::AntiVM() = default;
AntiVM::~AntiVM() { shutdown(); }

bool AntiVM::initialize() { return true; }
void AntiVM::shutdown() {}

std::vector<VMDetection> AntiVM::scanEnvironment() {
    std::vector<VMDetection> out;

    auto add = [&](const char* m, const char* d, bool s) {
        out.push_back({ m, d, s });
    };

    add("CPUID", "Hypervisor bit", detectCPUID());
    add("Drivers", "Drivers de VM conhecidos", detectDrivers());
    add("Processes", "Processos de VM conhecidos", detectProcesses());
    add("Windows", "Janelas de VM conhecidas", detectWindows());
    add("Registry", "Chaves de registro de VM", detectRegistryKeys());
    add("Files", "Arquivos/DLLs de VM", detectFiles());
    add("MAC", "MAC address de placa virtual", detectMacAddress());
    add("Hardware", "Configuração suspeita de hardware", detectHardwareAnomalies());

    return out;
}

bool AntiVM::isRunningInVM() {
    auto res = scanEnvironment();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isSuspicious; });
}

// ——————————————————————————— Técnicas ———————————————————————————

bool AntiVM::detectCPUID() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0; // Hypervisor bit
}

bool AntiVM::detectDrivers() {
    static const wchar_t* drivers[] = {
        L"VBoxMouse.sys", L"VBoxGuest.sys", L"VBoxSF.sys", L"VBoxVideo.sys",
        L"vmmouse.sys", L"vmhgfs.sys", L"vm3dmp.sys", L"vmci.sys", L"vmusbmouse.sys"
    };
    for (auto d : drivers) {
        if (checkDriver(d)) return true;
    }
    return false;
}

bool AntiVM::detectProcesses() {
    static const wchar_t* procs[] = {
        L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe", L"vmwaretray.exe",
        L"vmwareuser.exe", L"prl_tools.exe", L"xenservice.exe"
    };
    for (auto p : procs) {
        if (checkProcess(p)) return true;
    }
    return false;
}

bool AntiVM::detectWindows() {
    static const wchar_t* classes[] = {
        L"VBoxTrayToolWndClass", L"VMwareTrayClass", L"Qt5QWindowIcon"
    };
    for (auto c : classes) {
        if (checkWindow(c)) return true;
    }
    return false;
}

bool AntiVM::detectRegistryKeys() {
    static const wchar_t* keys[] = {
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"HARDWARE\\ACPI\\FADT\\VBOX__",
        L"HARDWARE\\ACPI\\RSDT\\VBOX__",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\ControlSet001\\Services\\VBoxGuest"
    };
    for (auto k : keys) {
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, k)) return true;
    }
    return false;
}

bool AntiVM::detectFiles() {
    static const wchar_t* files[] = {
        L"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        L"C:\\windows\\system32\\drivers\\vmhgfs.sys"
    };
    for (auto f : files) {
        if (checkFile(f)) return true;
    }
    return false;
}

bool AntiVM::detectMacAddress() {
    static const std::vector<std::string> prefixes = {
        "08:00:27", // VirtualBox
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "00:15:5D" // Hyper-V
    };

    return checkMacPrefix(prefixes);
}

bool AntiVM::detectHardwareAnomalies() {
    MEMORYSTATUSEX mem{ sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    // Heurísticas: pouca RAM (<2GB), poucos núcleos (<=2)
    if (mem.ullTotalPhys < (2ULL << 30)) return true;
    if (si.dwNumberOfProcessors <= 2) return true;

    return false;
}

// ——————————————————————————— Helpers ———————————————————————————

bool AntiVM::checkDriver(const std::wstring& name) {
    wchar_t path[MAX_PATH];
    if (GetSystemDirectoryW(path, MAX_PATH)) {
        std::wstring full = std::wstring(path) + L"\\drivers\\" + name;
        return GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES;
    }
    return false;
}

bool AntiVM::checkProcess(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{ sizeof(pe) };
    bool found = false;
    if (Process32First(snap, &pe)) {
        do {
            std::wstring exe(pe.szExeFile);
            std::transform(exe.begin(), exe.end(), exe.begin(), ::towlower);
            std::wstring lname = name;
            std::transform(lname.begin(), lname.end(), lname.begin(), ::towlower);
            if (exe.find(lname) != std::wstring::npos) { found = true; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool AntiVM::checkWindow(const std::wstring& className) {
    return FindWindowW(className.c_str(), nullptr) != nullptr;
}

bool AntiVM::checkRegistryKey(HKEY root, const std::wstring& path) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool AntiVM::checkFile(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool AntiVM::checkMacPrefix(const std::vector<std::string>& prefixes) {
    PIP_ADAPTER_INFO info = nullptr;
    ULONG len = 0;
    if (GetAdaptersInfo(nullptr, &len) != ERROR_BUFFER_OVERFLOW) return false;

    info = (PIP_ADAPTER_INFO)malloc(len);
    if (!info) return false;

    bool found = false;
    if (GetAdaptersInfo(info, &len) == NO_ERROR) {
        PIP_ADAPTER_INFO cur = info;
        while (cur) {
            char mac[18];
            sprintf_s(mac, "%02X:%02X:%02X", cur->Address[0], cur->Address[1], cur->Address[2]);
            std::string prefix(mac);
            for (const auto& p : prefixes) {
                if (prefix == p) {
                    found = true;
                    break;
                }
            }
            if (found) break;
            cur = cur->Next;
        }
    }
    free(info);
    return found;
}

} // namespace rgs::sdk::protection
