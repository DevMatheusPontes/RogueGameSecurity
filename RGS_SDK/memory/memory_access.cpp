#include "memory_access.hpp"
#include <cstring>
#include <algorithm>

namespace rgs::sdk::memory {

std::optional<std::vector<uint8_t>> MemoryAccess::read(uintptr_t address, std::size_t size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
                           buffer.data(), size, &bytesRead) || bytesRead != size) {
        return std::nullopt;
    }
    return buffer;
}

bool MemoryAccess::write(uintptr_t address, const std::vector<uint8_t>& data) {
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(address),
                            data.data(), data.size(), &bytesWritten) || bytesWritten != data.size()) {
        return false;
    }
    return true;
}

std::optional<std::string> MemoryAccess::read_string(uintptr_t address, std::size_t max_len) {
    auto raw = read(address, max_len);
    if (!raw) return std::nullopt;

    auto it = std::find(raw->begin(), raw->end(), '\0');
    if (it != raw->end()) raw->resize(std::distance(raw->begin(), it));

    return std::string(raw->begin(), raw->end());
}

bool MemoryAccess::write_string(uintptr_t address, const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    data.push_back('\0');
    return write(address, data);
}

#define DEFINE_READ_WRITE(type, name) \
std::optional<type> MemoryAccess::read_##name(uintptr_t address) { \
    return read_value<type>(address); \
} \
bool MemoryAccess::write_##name(uintptr_t address, type value) { \
    return write_value<type>(address, value); \
}

DEFINE_READ_WRITE(uint8_t,  byte)
DEFINE_READ_WRITE(uint16_t, word)
DEFINE_READ_WRITE(uint32_t, dword)
DEFINE_READ_WRITE(uint64_t, qword)
DEFINE_READ_WRITE(float,    float)
DEFINE_READ_WRITE(double,   double)

#undef DEFINE_READ_WRITE

template<typename T>
std::optional<T> MemoryAccess::read_value(uintptr_t address) {
    T value{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
                           &value, sizeof(T), &bytesRead) || bytesRead != sizeof(T)) {
        return std::nullopt;
    }
    return value;
}

template<typename T>
bool MemoryAccess::write_value(uintptr_t address, const T& value) {
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(address),
                            &value, sizeof(T), &bytesWritten) || bytesWritten != sizeof(T)) {
        return false;
    }
    return true;
}

template<typename T>
std::optional<T> MemoryAccess::read_at(uintptr_t base, std::ptrdiff_t offset) {
    return read_value<T>(base + offset);
}

template<typename T>
bool MemoryAccess::write_at(uintptr_t base, std::ptrdiff_t offset, const T& value) {
    return write_value<T>(base + offset, value);
}

std::optional<std::string> MemoryAccess::read_string_at(uintptr_t base, std::ptrdiff_t offset, std::size_t max_len) {
    return read_string(base + offset, max_len);
}

bool MemoryAccess::write_string_at(uintptr_t base, std::ptrdiff_t offset, const std::string& str) {
    return write_string(base + offset, str);
}

// Instanciação explícita
template std::optional<uint8_t>  MemoryAccess::read_value<uint8_t>(uintptr_t);
template std::optional<uint16_t> MemoryAccess::read_value<uint16_t>(uintptr_t);
template std::optional<uint32_t> MemoryAccess::read_value<uint32_t>(uintptr_t);
template std::optional<uint64_t> MemoryAccess::read_value<uint64_t>(uintptr_t);
template std::optional<float>    MemoryAccess::read_value<float>(uintptr_t);
template std::optional<double>   MemoryAccess::read_value<double>(uintptr_t);

template bool MemoryAccess::write_value<uint8_t>(uintptr_t, const uint8_t&);
template bool MemoryAccess::write_value<uint16_t>(uintptr_t, const uint16_t&);
template bool MemoryAccess::write_value<uint32_t>(uintptr_t, const uint32_t&);
template bool MemoryAccess::write_value<uint64_t>(uintptr_t, const uint64_t&);
template bool MemoryAccess::write_value<float>(uintptr_t, const float&);
template bool MemoryAccess::write_value<double>(uintptr_t, const double&);

template std::optional<uint8_t>  MemoryAccess::read_at<uint8_t>(uintptr_t, std::ptrdiff_t);
template std::optional<uint16_t> MemoryAccess::read_at<uint16_t>(uintptr_t, std::ptrdiff_t);
template std::optional<uint32_t> MemoryAccess::read_at<uint32_t>(uintptr_t, std::ptrdiff_t);
template std::optional<uint64_t> MemoryAccess::read_at<uint64_t>(uintptr_t, std::ptrdiff_t);
template std::optional<float>    MemoryAccess::read_at<float>(uintptr_t, std::ptrdiff_t);
template std::optional<double>   MemoryAccess::read_at<double>(uintptr_t, std::ptrdiff_t);

template bool MemoryAccess::write_at<uint8_t>(uintptr_t, std::ptrdiff_t, const uint8_t&);
template bool MemoryAccess::write_at<uint16_t>(uintptr_t, std::ptrdiff_t, const uint16_t&);
template bool MemoryAccess::write_at<uint32_t>(uintptr_t, std::ptrdiff_t, const uint32_t&);
template bool MemoryAccess::write_at<uint64_t>(uintptr_t, std::ptrdiff_t, const uint64_t&);
template bool MemoryAccess::write_at<float>(uintptr_t, std::ptrdiff_t, const float&);
template bool MemoryAccess::write_at<double>(uintptr_t, std::ptrdiff_t, const double&);

} // namespace rgs::sdk::memory
