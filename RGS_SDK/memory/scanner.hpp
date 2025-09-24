#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace rgs::sdk::memory {

class Scanner {
public:
    // Busca padrão binário com suporte a curingas (??)
    // Exemplo: "48 8B ?? ?? ?? 89"
    static std::optional<uintptr_t> find_pattern(uintptr_t start, std::size_t size, const std::string& pattern);

private:
    static bool match_pattern(const uint8_t* data, const std::vector<std::optional<uint8_t>>& pattern);
    static std::vector<std::optional<uint8_t>> parse_pattern(const std::string& pattern);
};

} // namespace rgs::sdk::memory
