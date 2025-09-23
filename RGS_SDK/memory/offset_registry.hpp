#pragma once

#include <string>
#include <map>
#include <cstdint>
#include <optional>
#include <mutex>

namespace rgs::sdk::memory {

    struct OffsetInfo {
        std::string name;
        uint32_t id;
        std::string version;
        uintptr_t address;
    };

    class OffsetRegistry {
    public:
        static OffsetRegistry& getInstance();

        void registerOffset(const std::string& name, uint32_t id, const std::string& version, uintptr_t address);
        
        std::optional<uintptr_t> getOffset(uint32_t id);
        std::optional<uintptr_t> getOffset(const std::string& name);

    private:
        OffsetRegistry() = default;

        std::map<uint32_t, OffsetInfo> m_offsetsById;
        std::map<std::string, OffsetInfo> m_offsetsByName;
        mutable std::mutex m_mutex;
    };

} // namespace rgs::sdk::memory
