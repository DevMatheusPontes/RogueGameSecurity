#pragma once

#ifdef RGS_CLIENT_EXPORTS
#define RGS_CLIENT_API __declspec(dllexport)
#else
#define RGS_CLIENT_API __declspec(dllimport)
#endif

namespace rgs::client {
    RGS_CLIENT_API void StartClient();
    RGS_CLIENT_API void StopClient();
}