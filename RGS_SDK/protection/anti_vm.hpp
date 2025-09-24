#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace rgs::sdk::protection {

struct VMDetection {
    std::string method;
    std::string description;
    bool isSuspicious;
};

class AntiVM {
public:
    AntiVM();
    ~AntiVM();

    bool initialize();
    void shutdown();

    std::vector<VMDetection> scanEnvironment();
    bool isRunningInVM();

private:
    // Técnicas de detecção
    bool detectCPUID();
    bool detectDrivers();
    bool detectProcesses();
    bool detectWindows();
    bool detectRegistryKeys();
    bool detectFiles();
    bool detectMacAddress();
    bool detectHardwareAnomalies();

    // Helpers
    bool checkDriver(const std::wstring& name);
    bool checkProcess(const std::wstring& name);
    bool checkWindow(const std::wstring& className);
    bool checkRegistryKey(HKEY root, const std::wstring& path);
    bool checkFile(const std::wstring& path);
    bool checkMacPrefix(const std::vector<std::string>& prefixes);
};

} // namespace rgs::sdk::protection
