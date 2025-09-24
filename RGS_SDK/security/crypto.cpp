#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace rgs::sdk::security {

static bool valid_sizes(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    return key.size() == 32 && iv.size() == 12;
}

std::optional<AesGcmResult> Crypto::aes256_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad
) {
    if (!valid_sizes(key, iv)) return std::nullopt;

    AesGcmResult out;
    out.ciphertext.resize(plaintext.size());
    out.tag.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    int ok = 1, len = 0, total = 0;

    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
    ok &= EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    if (!aad.empty()) {
        ok &= EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
    }

    if (ok) {
        ok &= EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len,
                                plaintext.data(), static_cast<int>(plaintext.size()));
        total += len;
    }

    if (ok) {
        ok &= EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + total, &len);
        total += len;
    }

    if (ok) {
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.tag.data());
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return std::nullopt;
    out.ciphertext.resize(total);
    return out;
}

std::optional<std::vector<uint8_t>> Crypto::aes256_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& aad
) {
    if (!valid_sizes(key, iv) || tag.size() != 16) return std::nullopt;

    std::vector<uint8_t> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    int ok = 1, len = 0, total = 0;

    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
    ok &= EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    if (!aad.empty()) {
        ok &= EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
    }

    if (ok) {
        ok &= EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                ciphertext.data(), static_cast<int>(ciphertext.size()));
        total += len;
    }

    if (ok) {
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                  const_cast<uint8_t*>(tag.data()));
        ok &= EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);
        total += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return std::nullopt;

    plaintext.resize(total);
    return plaintext;
}

} // namespace rgs::sdk::security
