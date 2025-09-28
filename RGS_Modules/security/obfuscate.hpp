#pragma once
// ======================================================
// Arquivo: obfuscate.hpp
// Módulo: RGS_Modules / security
// Descrição: Obfuscação segura de strings em tempo de compilação
// ======================================================

#include <array>
#include <string>
#include <cstddef>

namespace rgs::security {

// 🔐 Gerador de chave pseudoaleatória por índice
constexpr char dynamic_key(std::size_t index) {
    return static_cast<char>((index * 31 + 97) ^ 0x5C);
}

// 🔒 Classe de string obfuscada
template<std::size_t N>
class ObfuscatedString {
public:
    constexpr ObfuscatedString(const char(&str)[N]) {
        for (std::size_t i = 0; i < N; ++i) {
            data_[i] = str[i] ^ dynamic_key(i);
        }
    }

    std::string decrypt() {
        std::string result;
        result.resize(N - 1);
        for (std::size_t i = 0; i < N - 1; ++i) {
            result[i] = data_[i] ^ dynamic_key(i);
            data_[i] = result[i] ^ dynamic_key(i); // re-obfusca
        }
        return result;
    }

private:
    std::array<char, N> data_{};
};

// 🔧 Macro de uso
#define OBFUSCATE(str) rgs::security::ObfuscatedString<sizeof(str)>(str)

} // namespace rgs::security