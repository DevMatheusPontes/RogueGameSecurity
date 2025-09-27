#pragma once
#include <string>

namespace rgs::server {
    void start(const std::string& host, int port);
    void stop();
}