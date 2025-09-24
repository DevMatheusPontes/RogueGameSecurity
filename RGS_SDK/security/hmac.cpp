#include "hmac.hpp"
#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>

namespace rgs::sdk::security {

std::vector<uint8_t> Hmac::sha256(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& data) {
    unsigned int len = 0;
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         data.data(), data.size(),
         mac.data(), &len);

    mac.resize(len);
    return mac;
}

std::string Hmac::sha256_hex(const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& data) {
    auto mac = sha256(key, data);
    std::ostringstream oss;
    for (auto b : mac) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

} // namespace rgs::sdk::security
