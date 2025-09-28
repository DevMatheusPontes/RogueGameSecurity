#include "config.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

namespace rgs::config {

Config Config::loadFromFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return loadDefault();

    nlohmann::json j;
    f >> j;

    Config c;
    c.host    = j.value("host", "127.0.0.1");
    c.port    = j.value("port", 5000);
    c.threads = j.value("threads", 4);
    c.verbose = j.value("verbose", false);
    return c;
}

Config Config::loadDefault() {
    return {"127.0.0.1", 5000, 4, false};
}

}