#include "hkdf.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace rgs::sdk::security {

std::optional<std::vector<uint8_t>> HKDF::derive(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& info,
    std::size_t length) {

    std::vector<uint8_t> out(length);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return std::nullopt;

    int ok = 1;
    ok &= EVP_PKEY_derive_init(pctx);
    ok &= EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    ok &= EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size()));
    ok &= EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size()));
    ok &= EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size()));

    size_t outlen = out.size();
    ok &= EVP_PKEY_derive(pctx, out.data(), &outlen);
    EVP_PKEY_CTX_free(pctx);

    if (!ok || outlen != length) return std::nullopt;
    return out;
}

std::optional<SessionKeys> HKDF::derive_session_keys(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm,
    const std::string& info_context) {

    auto enc = derive(salt, ikm,
                      std::vector<uint8_t>(info_context.begin(), info_context.end()),
                      32);
    if (!enc) return std::nullopt;

    std::string info_mac = info_context + "/MAC";
    auto mac = derive(salt, ikm,
                      std::vector<uint8_t>(info_mac.begin(), info_mac.end()),
                      32);
    if (!mac) return std::nullopt;

    return SessionKeys{ *enc, *mac };
}

} // namespace rgs::sdk::security
