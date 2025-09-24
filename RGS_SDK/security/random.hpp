#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace rgs::sdk::security {

class Random {
public:
    // Bytes criptograficamente seguros
    static bool bytes(std::vector<uint8_t>& out, std::size_t len);

    // Gera um vetor já alocado
    static std::vector<uint8_t> bytes(std::size_t len);

    // Inteiros 32/64-bit
    static uint32_t u32();
    static uint64_t u64();

    // Hex string (lowercase) de bytes aleatórios
    static std::string hex(std::size_t len);

    // Gera chave AES-256 (32 bytes)
    static std::vector<uint8_t> key256();

    // Gera IV padrão GCM (12 bytes)
    static std::vector<uint8_t> iv12();
};

} // namespace rgs::sdk::security
