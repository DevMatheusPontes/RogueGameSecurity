#include "random.hpp"
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

namespace rgs::sdk::security {

bool Random::bytes(std::vector<uint8_t>& out, std::size_t len) {
    out.resize(len);
    return RAND_bytes(out.data(), static_cast<int>(len)) == 1;
}

std::vector<uint8_t> Random::bytes(std::size_t len) {
    std::vector<uint8_t> out(len);
    RAND_bytes(out.data(), static_cast<int>(len));
    return out;
}

uint32_t Random::u32() {
    uint32_t v;
    RAND_bytes(reinterpret_cast<unsigned char*>(&v), sizeof(v));
    return v;
}

uint64_t Random::u64() {
    uint64_t v;
    RAND_bytes(reinterpret_cast<unsigned char*>(&v), sizeof(v));
    return v;
}

std::string Random::hex(std::size_t len) {
    auto b = bytes(len);
    std::ostringstream oss;
    for (auto c : b) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

std::vector<uint8_t> Random::key256() {
    return bytes(32);
}

std::vector<uint8_t> Random::iv12() {
    return bytes(12);
}

} // namespace rgs::sdk::security
