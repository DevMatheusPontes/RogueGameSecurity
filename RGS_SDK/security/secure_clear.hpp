#pragma once

#include <vector>
#include <cstdint>

namespace rgs::sdk::security {

// Limpa buffer de forma segura (evita otimizações)
inline void secure_memzero(void* ptr, std::size_t len) {
#if defined(_MSC_VER)
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) { *p++ = 0; }
#else
    // OPENSSL_cleanse disponível via OpenSSL
    extern "C" void OPENSSL_cleanse(void* ptr, std::size_t len);
    OPENSSL_cleanse(ptr, len);
#endif
}

// Versão para std::vector<uint8_t>
inline void secure_clear(std::vector<uint8_t>& v) {
    if (!v.empty()) secure_memzero(v.data(), v.size());
    v.clear();
    v.shrink_to_fit();
}

} // namespace rgs::sdk::security
