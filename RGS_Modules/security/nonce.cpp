#include "nonce.hpp"

#if defined(_WIN32)
  #include <Windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#endif

#include <random>

namespace rgs::utils {

std::vector<std::uint8_t> Nonce::bytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(nullptr,
                                      reinterpret_cast<PUCHAR>(out.data()),
                                      static_cast<ULONG>(out.size()),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        // Fallback para std::random_device
        std::random_device rd;
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<std::uint8_t>(rd());
        }
    }
#else
    // Sistemas não-Windows: usar std::random_device como fonte
    std::random_device rd;
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(rd());
    }
#endif

    return out;
}

std::string Nonce::to_hex(std::string_view bytes_view) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes_view.size() * 2);

    for (unsigned char c : bytes_view) {
        out.push_back(hex[(c >> 4) & 0x0F]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

std::string Nonce::to_hex(const std::vector<std::uint8_t>& bytes_vec) {
    std::string_view sv(reinterpret_cast<const char*>(bytes_vec.data()), bytes_vec.size());
    return to_hex(sv);
}

void Nonce::wipe(std::vector<std::uint8_t>& v) noexcept {
    if (v.empty()) return;
#if defined(_WIN32)
    SecureZeroMemory(v.data(), v.size());
#else
    volatile std::uint8_t* p = v.data();
    for (std::size_t i = 0; i < v.size(); ++i) p[i] = 0;
#endif
    v.clear();
    v.shrink_to_fit();
}

} // namespace rgs::utils