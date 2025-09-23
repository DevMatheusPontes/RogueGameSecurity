#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>

namespace rgs::sdk::security {

    /**
     * @brief Computes the CRC32 hash of a data buffer.
     * @param data The data to hash.
     * @return The CRC32 hash.
     */
    uint32_t computeCrc32(const std::vector<std::byte>& data);

    /**
     * @brief Verifies the CRC32 hash of a data buffer.
     * @param data The data to verify.
     * @param expectedCrc32 The expected CRC32 hash.
     * @return True if the hash matches, false otherwise.
     */
    bool verifyCrc32(const std::vector<std::byte>& data, uint32_t expectedCrc32);

} // namespace rgs::sdk::security
