#include <windows.h>
#include "server.hpp"

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        rgs::server::start("127.0.0.1", 7777);
        break;
    case DLL_PROCESS_DETACH:
        rgs::server::stop();
        break;
    }
    return TRUE;
}