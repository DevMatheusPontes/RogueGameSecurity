#pragma once

#include <vector>
#include <cstdint>

namespace rgs::sdk::memory {

    /**
     * @brief Resolves a multi-level pointer.
     * @param baseAddress The base address.
     * @param offsets The vector of offsets.
     * @return The final address, or 0 if any pointer in the chain is invalid.
     */
    uintptr_t resolvePointer(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets);

} // namespace rgs::sdk::memory
