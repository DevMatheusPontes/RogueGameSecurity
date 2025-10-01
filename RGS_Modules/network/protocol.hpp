#pragma once

#include <cstdint>
#include <array>
#include <string_view>
#include <optional>

namespace rgs::network {

// Estrutura fixa do cabeçalho de protocolo
struct ProtocolHeader {
    std::uint32_t magic;       // Identificador fixo
    std::uint16_t version;     // Versão do protocolo
    std::uint16_t header_size; // Tamanho do cabeçalho
    std::uint16_t service;     // Código do serviço
    std::uint16_t flags;       // Flags de controle
    std::uint32_t payload_len; // Tamanho do payload
    std::uint32_t crc32;       // CRC32 do payload
    std::uint32_t reserved;    // Reservado para futuro uso
};

class Protocol {
public:
    static constexpr std::uint32_t MAGIC = 0x52475321; // "RGS!" em hex
    static constexpr std::uint16_t VERSION = 1;
    static constexpr std::size_t HEADER_SIZE = sizeof(ProtocolHeader);

    // Serializa cabeçalho em buffer (little-endian)
    static void encode_header(const ProtocolHeader& hdr, std::array<std::uint8_t, HEADER_SIZE>& out);

    // Desserializa cabeçalho de buffer
    static std::optional<ProtocolHeader> decode_header(const std::uint8_t* data, std::size_t len);

    // Calcula CRC32 de um buffer
    static std::uint32_t crc32(const std::uint8_t* data, std::size_t len);
};

} // namespace rgs::network