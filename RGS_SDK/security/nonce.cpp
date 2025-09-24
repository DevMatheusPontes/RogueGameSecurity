#include "nonce.hpp"
#include "random.hpp"
#include <cstring>

namespace rgs::sdk::security {

NonceGenerator::NonceGenerator()
    : prefix_(Random::u32()), ctr_(0ULL) {}

std::vector<uint8_t> NonceGenerator::next_iv() {
    std::vector<uint8_t> iv(12);
    std::memcpy(iv.data(), &prefix_, sizeof(prefix_));
    uint64_t c = ctr_.fetch_add(1, std::memory_order_relaxed);
    std::memcpy(iv.data() + sizeof(prefix_), &c, sizeof(c));
    return iv;
}

void NonceGenerator::reset() {
    ctr_.store(0ULL, std::memory_order_relaxed);
}

} // namespace rgs::sdk::security
