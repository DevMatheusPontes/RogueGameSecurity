#include "scanner.hpp"
#include "memory_access.hpp"

#include <sstream>
#include <iomanip>

namespace rgs::sdk::memory {

std::vector<std::optional<uint8_t>> Scanner::parse_pattern(const std::string& pattern) {
    std::vector<std::optional<uint8_t>> result;
    std::istringstream iss(pattern);
    std::string byte;

    while (iss >> byte) {
        if (byte == "??" || byte == "?") {
            result.push_back(std::nullopt);
        } else {
            uint8_t val = static_cast<uint8_t>(std::stoul(byte, nullptr, 16));
            result.push_back(val);
        }
    }

    return result;
}

bool Scanner::match_pattern(const uint8_t* data, const std::vector<std::optional<uint8_t>>& pattern) {
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] && data[i] != *pattern[i]) {
            return false;
        }
    }
    return true;
}

std::optional<uintptr_t> Scanner::find_pattern(uintptr_t start, std::size_t size, const std::string& pattern) {
    auto parsed = parse_pattern(pattern);
    if (parsed.empty() || parsed.size() > size) return std::nullopt;

    auto buffer_opt = MemoryAccess::read(start, size);
    if (!buffer_opt) return std::nullopt;

    const auto& buffer = *buffer_opt;
    for (std::size_t i = 0; i <= buffer.size() - parsed.size(); ++i) {
        if (match_pattern(&buffer[i], parsed)) {
            return start + i;
        }
    }

    return std::nullopt;
}

} // namespace rgs::sdk::memory
