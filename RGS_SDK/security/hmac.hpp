#pragma once

#include <vector>
#include <string>

namespace rgs::sdk::security {

class Hmac {
public:
    // key: bytes arbitrários (ex.: 32 bytes)
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data);

    static std::string sha256_hex(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& data);
};

} // namespace rgs::sdk::security
