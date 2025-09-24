#include "network/message.hpp"
#include <cstring>

namespace rgs::sdk::network {

Message::Message(MessageType type) {
    std::memset(&header_, 0, sizeof(header_));
    header_.magic = MAGIC_VALUE;
    header_.type  = static_cast<uint32_t>(type);
}

void Message::set_plain(const std::vector<uint8_t>& data) {
    plaintext_ = data;
}

void Message::set_plain(std::vector<uint8_t>&& data) {
    plaintext_ = std::move(data);
}

bool Message::encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    if (key.size() != 32 || iv.size() != 12) return false;

    header_.magic = MAGIC_VALUE;
    header_.length = static_cast<uint32_t>(plaintext_.size());
    std::memcpy(header_.iv, iv.data(), iv.size());

    std::vector<uint8_t> aad(sizeof(PacketHeader) - sizeof(header_.tag));
    std::memcpy(aad.data(), &header_, aad.size());

    auto enc = rgs::sdk::security::Crypto::aes256_gcm_encrypt(key, iv, plaintext_, aad);
    if (!enc) return false;

    ciphertext_ = std::move(enc->ciphertext);
    std::memcpy(header_.tag, enc->tag.data(), enc->tag.size());
    header_.length = static_cast<uint32_t>(ciphertext_.size());

    rgs::sdk::security::secure_clear(plaintext_);
    return true;
}

bool Message::decrypt(const std::vector<uint8_t>& key) {
    if (key.size() != 32) return false;
    if (header_.magic != MAGIC_VALUE) return false;

    std::vector<uint8_t> aad(sizeof(PacketHeader) - sizeof(header_.tag));
    std::memcpy(aad.data(), &header_, aad.size());

    auto dec = rgs::sdk::security::Crypto::aes256_gcm_decrypt(
        key,
        std::vector<uint8_t>(header_.iv, header_.iv + 12),
        ciphertext_,
        std::vector<uint8_t>(header_.tag, header_.tag + 16),
        aad
    );
    if (!dec) return false;

    plaintext_ = std::move(*dec);
    return true;
}

std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> out;
    out.resize(sizeof(PacketHeader) + ciphertext_.size());

    std::memcpy(out.data(), &header_, sizeof(PacketHeader));
    if (!ciphertext_.empty()) {
        std::memcpy(out.data() + sizeof(PacketHeader),
                    ciphertext_.data(), ciphertext_.size());
    }
    return out;
}

std::optional<Message> Message::deserialize(const uint8_t* data, std::size_t size) {
    if (!data || size < sizeof(PacketHeader)) return std::nullopt;

    Message msg;
    std::memcpy(&msg.header_, data, sizeof(PacketHeader));

    if (msg.header_.magic != MAGIC_VALUE) return std::nullopt;

    std::size_t csz = static_cast<std::size_t>(msg.header_.length);
    if (sizeof(PacketHeader) + csz > size) return std::nullopt;

    msg.ciphertext_.resize(csz);
    if (csz) {
        std::memcpy(msg.ciphertext_.data(),
                    data + sizeof(PacketHeader), csz);
    }
    return msg;
}

} // namespace rgs::sdk::network
