#pragma once

#include <windows.h>
#include <vector>
#include <optional>
#include <cstdint>

namespace rgs::sdk::memory {

    /**
     * @brief Checks if a memory address is valid to be read.
     * @param address The address to check.
     * @param size The size of the memory block to check.
     * @return True if the memory is readable, false otherwise.
     */
    bool isReadable(const void* address, size_t size = 1);

    /**
     * @brief Reads a value of type T from a given memory address.
     * @tparam T The type of the value to read.
     * @param address The address to read from.
     * @return An optional containing the value if successful, otherwise std::nullopt.
     */
    template<typename T>
    std::optional<T> read(uintptr_t address) {
        T value{};
        if (!isReadable(reinterpret_cast<const void*>(address), sizeof(T))) {
            return std::nullopt;
        }

        __try {
            value = *reinterpret_cast<T*>(address);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return std::nullopt;
        }
        return value;
    }

    /**
     * @brief Writes a value of type T to a given memory address.
     * @tparam T The type of the value to write.
     * @param address The address to write to.
     * @param value The value to write.
     * @return True if the write was successful, false otherwise.
     */
    template<typename T>
    bool write(uintptr_t address, T value) {
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_READWRITE, &oldProtect)) {
            return false;
        }

        __try {
            *reinterpret_cast<T*>(address) = value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
            return false;
        }

        VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
        return true;
    }

    std::vector<std::byte> readBuffer(uintptr_t address, size_t size);
    bool writeBuffer(uintptr_t address, const std::vector<std::byte>& data);

} // namespace rgs::sdk::memory
