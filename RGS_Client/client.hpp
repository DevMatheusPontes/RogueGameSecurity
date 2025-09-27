#pragma once
#include <string>

namespace rgs::client {
    void start(const std::string& host, int port);
    void stop();
}