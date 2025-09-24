#pragma once

#include <cstdint>
#include <vector>
#include <optional>

namespace rgs::sdk::memory {

class PointerUtils {
public:
    // Resolve cadeia de ponteiros: base + offset1 → leitura → + offset2 → ...
    static std::optional<uintptr_t> resolve_pointer_chain(uintptr_t base, const std::vector<std::ptrdiff_t>& offsets);
};

} // namespace rgs::sdk::memory
