#include "packet_builder.hpp"

namespace rgs::network {

Message PacketBuilder::from_string(std::uint16_t service, std::string_view text,
                                   std::uint16_t flags) {
    std::vector<std::uint8_t> payload(text.size());
    const auto* src = reinterpret_cast<const std::uint8_t*>(text.data());
    for (std::size_t i = 0; i < text.size(); ++i) {
        payload[i] = src[i];
    }
    return Message(service, flags, std::move(payload));
}

Message PacketBuilder::from_secure_string(std::uint16_t service,
                                          rgs::security::SecureString& s,
                                          std::uint16_t flags) {
    std::vector<std::uint8_t> payload;
    s.with_decrypted_view([&](std::string_view view) {
        payload.resize(view.size());
        const auto* src = reinterpret_cast<const std::uint8_t*>(view.data());
        for (std::size_t i = 0; i < view.size(); ++i) {
            payload[i] = src[i];
        }
        // Ao sair do callback, o SecureString já fará wipe/recifra.
    });
    return Message(service, flags, std::move(payload));
}

Message PacketBuilder::from_bytes(std::uint16_t service,
                                  const std::vector<std::uint8_t>& data,
                                  std::uint16_t flags) {
    std::vector<std::uint8_t> payload(data.begin(), data.end());
    return Message(service, flags, std::move(payload));
}

Message PacketBuilder::from_bytes(std::uint16_t service,
                                  const std::uint8_t* data, std::size_t len,
                                  std::uint16_t flags) {
    std::vector<std::uint8_t> payload(len);
    for (std::size_t i = 0; i < len; ++i) {
        payload[i] = data[i];
    }
    return Message(service, flags, std::move(payload));
}

} // namespace rgs::network