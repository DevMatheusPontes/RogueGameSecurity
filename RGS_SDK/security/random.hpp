#pragma once

#include <cstdint>
#include <vector>

namespace rgs::sdk::security {

    /**
     * @brief Generates a block of cryptographically secure random bytes.
     * @param size The number of random bytes to generate.
     * @return A vector containing the random bytes.
     */
    std::vector<std::byte> generateRandomBytes(size_t size);

    /**
     * @brief Generates a cryptographically secure random 64-bit integer.
     * @return A random uint64_t.
     */
    uint64_t generateNonce();

} // namespace rgs::sdk::security
