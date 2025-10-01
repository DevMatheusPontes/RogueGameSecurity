#include "pch.h"
#include "client.hpp"
#include <thread>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        std::thread([](){ rgs::client::StartClient(); }).detach();
        break;
    case DLL_PROCESS_DETACH:
        rgs::client::StopClient();
        break;
    }
    return TRUE;
}