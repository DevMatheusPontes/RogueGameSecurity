#pragma once

#include <unordered_map>
#include <string>
#include <optional>
#include <cstdint>
#include <mutex>

namespace rgs::sdk::memory {

class OffsetRegistry {
public:
    // Registra um offset com nome
    void register_offset(const std::string& name, uintptr_t address);

    // Obtém um offset por nome
    std::optional<uintptr_t> get_offset(const std::string& name) const;

    // Remove um offset
    void unregister_offset(const std::string& name);

    // Lista todos os offsets registrados
    std::unordered_map<std::string, uintptr_t> list_all() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, uintptr_t> offsets_;
};

} // namespace rgs::sdk::memory
