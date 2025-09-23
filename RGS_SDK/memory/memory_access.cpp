#include "memory_access.hpp"
#include "../utils/config.hpp"

namespace rgs::sdk::memory {

    bool isReadable(const void* address, size_t size) {
        if (address == nullptr) return false;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE) {
            return false;
        }

        // Check if the entire range is readable
        size_t blockOffset = (uintptr_t)address - (uintptr_t)mbi.BaseAddress;
        size_t readableSize = mbi.RegionSize - blockOffset;
        return size <= readableSize;
    }

    std::vector<std::byte> readBuffer(uintptr_t address, size_t size) {
        auto& config = utils::Config::getInstance();
        size_t maxSize = config.get<size_t>("memory.max_read_size").value_or(4096);
        if (size > maxSize) {
            return {};
        }

        if (!isReadable(reinterpret_cast<const void*>(address), size)) {
            return {};
        }

        std::vector<std::byte> buffer(size);
        __try {
            memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return {};
        }

        return buffer;
    }

    bool writeBuffer(uintptr_t address, const std::vector<std::byte>& data) {
        auto& config = utils::Config::getInstance();
        size_t maxSize = config.get<size_t>("memory.max_write_size").value_or(4096);
        if (data.size() > maxSize) {
            return false;
        }

        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(address), data.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        __try {
            memcpy(reinterpret_cast<void*>(address), data.data(), data.size());
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            VirtualProtect(reinterpret_cast<void*>(address), data.size(), oldProtect, &oldProtect);
            return false;
        }

        VirtualProtect(reinterpret_cast<void*>(address), data.size(), oldProtect, &oldProtect);
        return true;
    }

} // namespace rgs::sdk::memory
