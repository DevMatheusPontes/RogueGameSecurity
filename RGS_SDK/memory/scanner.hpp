#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <optional>

namespace rgs::sdk::memory {

    /**
     * @brief Scans a memory region for a byte pattern.
     * @param moduleBase The base address of the module to scan.
     * @param pattern The byte pattern to search for.
     * @param mask The mask for the pattern (e.g., "x?x?"). 'x' means match, '?' means wildcard.
     * @return An optional containing the address of the found pattern, otherwise std::nullopt.
     */
    std::optional<uintptr_t> scanPattern(uintptr_t moduleBase, const std::string& pattern, const std::string& mask);

} // namespace rgs::sdk::memory
