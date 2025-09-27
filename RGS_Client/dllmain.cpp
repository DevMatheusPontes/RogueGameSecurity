#include <windows.h>
#include <thread>
#include "client.hpp"

DWORD WINAPI ClientThread(LPVOID) {
    rgs::client::start("127.0.0.1", 7777);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ClientThread, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        rgs::client::stop();
        break;
    }
    return TRUE;
}