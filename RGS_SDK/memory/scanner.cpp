#include "scanner.hpp"
#include <psapi.h>

namespace rgs::sdk::memory {

    std::optional<uintptr_t> scanPattern(uintptr_t moduleBase, const std::string& pattern, const std::string& mask) {
        MODULEINFO moduleInfo;
        if (!GetModuleInformation(GetCurrentProcess(), (HMODULE)moduleBase, &moduleInfo, sizeof(moduleInfo))) {
            return std::nullopt;
        }

        uintptr_t scanAddress = moduleBase;
        uintptr_t scanEnd = moduleBase + moduleInfo.SizeOfImage;
        size_t patternLen = mask.length();

        for (uintptr_t i = scanAddress; i < scanEnd - patternLen; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask[j] != '?' && pattern[j] != *(char*)(i + j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }

        return std::nullopt;
    }

} // namespace rgs::sdk::memory
