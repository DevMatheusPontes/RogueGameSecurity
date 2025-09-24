#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include <string>
#include <windows.h>

namespace rgs::sdk::memory {

class MemoryAccess {
public:
    // Leitura genérica
    static std::optional<std::vector<uint8_t>> read(uintptr_t address, std::size_t size);
    static std::optional<std::string> read_string(uintptr_t address, std::size_t max_len = 256);

    // Escrita genérica
    static bool write(uintptr_t address, const std::vector<uint8_t>& data);
    static bool write_string(uintptr_t address, const std::string& str);

    // Tipos primitivos
    static std::optional<uint8_t>  read_byte(uintptr_t address);
    static std::optional<uint16_t> read_word(uintptr_t address);
    static std::optional<uint32_t> read_dword(uintptr_t address);
    static std::optional<uint64_t> read_qword(uintptr_t address);
    static std::optional<float>    read_float(uintptr_t address);
    static std::optional<double>   read_double(uintptr_t address);

    static bool write_byte(uintptr_t address, uint8_t value);
    static bool write_word(uintptr_t address, uint16_t value);
    static bool write_dword(uintptr_t address, uint32_t value);
    static bool write_qword(uintptr_t address, uint64_t value);
    static bool write_float(uintptr_t address, float value);
    static bool write_double(uintptr_t address, double value);

    // Leitura/escrita com offset
    template<typename T>
    static std::optional<T> read_at(uintptr_t base, std::ptrdiff_t offset);

    template<typename T>
    static bool write_at(uintptr_t base, std::ptrdiff_t offset, const T& value);

    static std::optional<std::string> read_string_at(uintptr_t base, std::ptrdiff_t offset, std::size_t max_len = 256);
    static bool write_string_at(uintptr_t base, std::ptrdiff_t offset, const std::string& str);

    // Templates genéricos
    template<typename T>
    static std::optional<T> read_value(uintptr_t address);

    template<typename T>
    static bool write_value(uintptr_t address, const T& value);
};

} // namespace rgs::sdk::memory
