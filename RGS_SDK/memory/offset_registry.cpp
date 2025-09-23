#include "offset_registry.hpp"

namespace rgs::sdk::memory {

    OffsetRegistry& OffsetRegistry::getInstance() {
        static OffsetRegistry instance;
        return instance;
    }

    void OffsetRegistry::registerOffset(const std::string& name, uint32_t id, const std::string& version, uintptr_t address) {
        std::lock_guard<std::mutex> lock(m_mutex);
        OffsetInfo info{name, id, version, address};
        m_offsetsById[id] = info;
        m_offsetsByName[name] = info;
    }

    std::optional<uintptr_t> OffsetRegistry::getOffset(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_offsetsById.find(id);
        if (it != m_offsetsById.end()) {
            return it->second.address;
        }
        return std::nullopt;
    }

    std::optional<uintptr_t> OffsetRegistry::getOffset(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_offsetsByName.find(name);
        if (it != m_offsetsByName.end()) {
            return it->second.address;
        }
        return std::nullopt;
    }

} // namespace rgs::sdk::memory
