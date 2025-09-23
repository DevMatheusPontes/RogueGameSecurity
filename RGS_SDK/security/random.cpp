#include "random.hpp"
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace rgs::sdk::security {

    std::vector<std::byte> generateRandomBytes(size_t size) {
        std::vector<std::byte> buffer(size);
        HCRYPTPROV hCryptProv = 0;

        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, static_cast<DWORD>(buffer.size()), reinterpret_cast<BYTE*>(buffer.data()));
            CryptReleaseContext(hCryptProv, 0);
        }

        return buffer;
    }

    uint64_t generateNonce() {
        uint64_t nonce = 0;
        HCRYPTPROV hCryptProv = 0;

        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, sizeof(nonce), reinterpret_cast<BYTE*>(&nonce));
            CryptReleaseContext(hCryptProv, 0);
        }
        return nonce;
    }

} // namespace rgs::sdk::security
