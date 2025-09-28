#pragma once

#include <string>
#include <cstdint>

namespace rgs::config {

struct Config {
    std::string host;
    uint16_t port;
    std::size_t threads;
    bool verbose;

    static Config loadFromFile(const std::string& path);
    static Config loadDefault();
};

}