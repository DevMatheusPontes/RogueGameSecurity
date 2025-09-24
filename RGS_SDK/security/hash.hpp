#pragma once

#include <string>
#include <vector>

namespace rgs::sdk::security {

class Hash {
public:
    // Gera SHA1 (20 bytes) em formato hexadecimal
    static std::string sha1(const std::string& input);

    // Gera SHA256 (32 bytes) em formato hexadecimal
    static std::string sha256(const std::string& input);

private:
    static std::string to_hex(const std::vector<unsigned char>& data);
};

} // namespace rgs::sdk::security
