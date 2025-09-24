#include "pointer_utils.hpp"
#include "memory_access.hpp"

namespace rgs::sdk::memory {

std::optional<uintptr_t> PointerUtils::resolve_pointer_chain(uintptr_t base, const std::vector<std::ptrdiff_t>& offsets) {
    uintptr_t current = base;

    for (std::size_t i = 0; i < offsets.size(); ++i) {
        current += offsets[i];

        // Se não for o último, precisamos ler o ponteiro
        if (i < offsets.size() - 1) {
            auto next = MemoryAccess::read_value<uintptr_t>(current);
            if (!next) return std::nullopt;
            current = *next;
        }
    }

    return current;
}

} // namespace rgs::sdk::memory
