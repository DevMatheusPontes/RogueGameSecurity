#include "offset_registry.hpp"

namespace rgs::sdk::memory {

void OffsetRegistry::register_offset(const std::string& name, uintptr_t address) {
    std::lock_guard<std::mutex> lock(mutex_);
    offsets_[name] = address;
}

std::optional<uintptr_t> OffsetRegistry::get_offset(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = offsets_.find(name);
    if (it != offsets_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void OffsetRegistry::unregister_offset(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    offsets_.erase(name);
}

std::unordered_map<std::string, uintptr_t> OffsetRegistry::list_all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return offsets_;
}

} // namespace rgs::sdk::memory
