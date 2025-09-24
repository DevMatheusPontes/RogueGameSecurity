#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include <string>
#include <cstring>

#include "network/protocol.hpp"
#include "security/crypto.hpp"
#include "security/secure_clear.hpp"

namespace rgs::sdk::network {

class Message {
public:
    Message() = default;
    explicit Message(MessageType type);

    void set_plain(const std::vector<uint8_t>& data);
    void set_plain(std::vector<uint8_t>&& data);

    bool encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    bool decrypt(const std::vector<uint8_t>& key);

    std::vector<uint8_t> serialize() const;
    static std::optional<Message> deserialize(const uint8_t* data, std::size_t size);

    const PacketHeader& header() const { return header_; }
    PacketHeader& header() { return header_; }

    const std::vector<uint8_t>& plaintext() const { return plaintext_; }
    const std::vector<uint8_t>& ciphertext() const { return ciphertext_; }

    MessageType type() const { return static_cast<MessageType>(header_.type); }
    void set_type(MessageType t) { header_.type = static_cast<uint32_t>(t); }

private:
    PacketHeader header_{};
    std::vector<uint8_t> plaintext_;
    std::vector<uint8_t> ciphertext_;
};

} // namespace rgs::sdk::network
