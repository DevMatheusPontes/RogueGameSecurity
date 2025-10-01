#pragma once

#ifdef RGS_SERVER_EXPORTS
#define RGS_SERVER_API __declspec(dllexport)
#else
#define RGS_SERVER_API __declspec(dllimport)
#endif

namespace rgs::server {
    RGS_SERVER_API void StartServer();
    RGS_SERVER_API void StopServer();
}