#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string_view>
#include <functional>
#include <random>

#if defined(_WIN32)
  #include <Windows.h>
#endif

#include "security/obfuscate.hpp"

namespace rgs::security {

// SecureString: armazena cifrado, expõe texto apenas durante um callback,
// e limpa/recifra logo após o uso. Evitar literais cruas; usar obfuscate.
class SecureString {
public:
    explicit SecureString(std::string_view initial) {
        init_cipher(initial);
    }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept
        : cipher_(std::move(other.cipher_)), key_(other.key_) {
        other.key_ = 0;
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            wipe_all();
            cipher_ = std::move(other.cipher_);
            key_ = other.key_;
            other.key_ = 0;
        }
        return *this;
    }

    ~SecureString() {
        wipe_all();
    }

    std::size_t size() const noexcept { return cipher_.size(); }

    // Exposição segura via callback; garante wipe e recifra ao sair.
    void with_decrypted_view(const std::function<void(std::string_view)>& fn) {
        if (cipher_.empty()) {
            fn({});
            return;
        }

        std::vector<std::uint8_t> plain(cipher_.size());
        for (std::size_t i = 0; i < cipher_.size(); ++i)
            plain[i] = cipher_[i] ^ key_;

        std::string_view view(reinterpret_cast<const char*>(plain.data()), plain.size());
        fn(view);

        wipe_bytes(plain);
        reencrypt(view);
    }

    void replace(std::string_view new_text) {
        wipe_all();
        init_cipher(new_text);
    }

    // Construção a partir de tipo ofuscado de build (extensão simples).
    template <typename T>
    static SecureString from_obfuscated(const T& obf) {
        std::vector<std::uint8_t> tmp;
        obf.decrypt_to(tmp); // conteúdo plain em tmp
        SecureString s(std::string_view(reinterpret_cast<const char*>(tmp.data()), tmp.size()));
        wipe_bytes(tmp);
        return s;
    }

private:
    std::vector<std::uint8_t> cipher_;
    std::uint8_t key_ = 0;

    static void wipe_bytes(std::vector<std::uint8_t>& v) noexcept {
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

    static std::uint8_t generate_key() noexcept {
        std::random_device rd;
        auto k = static_cast<std::uint8_t>(rd() & 0xFFu);
        return k == 0 ? 0xA7 : k; // evita chave zero
    }

    void init_cipher(std::string_view text) {
        key_ = generate_key();
        cipher_.resize(text.size());
        const auto* src = reinterpret_cast<const std::uint8_t*>(text.data());
        for (std::size_t i = 0; i < text.size(); ++i)
            cipher_[i] = src[i] ^ key_;
    }

    void reencrypt(std::string_view plain) {
        key_ = rotate_key(key_);
        cipher_.resize(plain.size());
        const auto* src = reinterpret_cast<const std::uint8_t*>(plain.data());
        for (std::size_t i = 0; i < plain.size(); ++i)
            cipher_[i] = src[i] ^ key_;
    }

    static std::uint8_t rotate_key(std::uint8_t k) noexcept {
        // rotação simples para reduzir padrões previsíveis
        return static_cast<std::uint8_t>(((k << 5) | (k >> 3)) ^ 0x5D);
    }

    void wipe_all() noexcept {
        wipe_bytes(cipher_);
        key_ = 0;
    }
};

} // namespace rgs::security