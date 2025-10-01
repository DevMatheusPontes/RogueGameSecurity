#include "config.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace rgs::config {

bool Config::load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        // Remove espaços extras
        line.erase(std::remove_if(line.begin(), line.end(),
                                  [](unsigned char c){ return c == '\r' || c == '\n'; }),
                   line.end());

        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        // Trim espaços
        auto trim = [](std::string& s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                            [](unsigned char ch){ return !std::isspace(ch); }));
            s.erase(std::find_if(s.rbegin(), s.rend(),
                                 [](unsigned char ch){ return !std::isspace(ch); }).base(),
                    s.end());
        };
        trim(key);
        trim(value);

        if (!key.empty()) {
            values_[key] = value;
        }
    }
    return true;
}

std::optional<std::string> Config::get(std::string_view key) const {
    auto it = values_.find(std::string(key));
    if (it != values_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<rgs::security::SecureString> Config::get_secure(std::string_view key) const {
    auto it = values_.find(std::string(key));
    if (it != values_.end()) {
        return rgs::security::SecureString(it->second);
    }
    return std::nullopt;
}

void Config::set(std::string key, std::string value) {
    values_[std::move(key)] = std::move(value);
}

} // namespace rgs::config