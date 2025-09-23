#include "pointer_utils.hpp"
#include "memory_access.hpp"

namespace rgs::sdk::memory {

    uintptr_t resolvePointer(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets) {
        uintptr_t addr = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            auto readResult = read<uintptr_t>(addr);
            if (!readResult) return 0;
            addr = *readResult + offsets[i];
        }
        return addr;
    }

} // namespace rgs::sdk::memory
