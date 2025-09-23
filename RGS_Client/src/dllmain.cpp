#include <windows.h>
#include "client_core.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            rgs::client::ClientCore::getInstance().start();
            break;
        case DLL_PROCESS_DETACH:
            rgs::client::ClientCore::getInstance().stop();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
