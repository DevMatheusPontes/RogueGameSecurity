#pragma once

#include "protocol.hpp"
#include <vector>
#include <string>
#include <cstddef>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <sstream>

namespace rgs::sdk::network {

    class Message {
    public:
        Message() = default;

        Message(MessageType type, const std::vector<std::byte>& payload, MessageFlags flags = MessageFlags::None)
            : m_payload(payload) {
            m_header.magic = MAGIC_VALUE;
            m_header.version = PROTOCOL_VERSION;
            m_header.type = type;
            m_header.flags = flags;
            m_header.length = static_cast<uint32_t>(payload.size());
            m_header.nonce = 0; // Nonce should be set by the session/transport layer
            m_header.crc32 = calculateCrc32(payload);
        }

        const ProtocolHeader& getHeader() const { return m_header; }
        ProtocolHeader& getHeader() { return m_header; }

        const std::vector<std::byte>& getPayload() const { return m_payload; }
        std::vector<std::byte>& getPayload() { return m_payload; }

        /**
         * @brief Serializes the message payload into a byte vector.
         * @tparam T The type of the data to serialize.
         * @param data The data to serialize.
         * @return A byte vector containing the serialized data.
         */
        template<typename T>
        static std::vector<std::byte> serialize(const T& data) {
            std::stringstream ss;
            boost::archive::binary_oarchive oa(ss);
            oa << data;
            const std::string& str = ss.str();
            const auto* bytes = reinterpret_cast<const std::byte*>(str.data());
            return {bytes, bytes + str.size()};
        }

        /**
         * @brief Deserializes a byte vector into a specific type.
         * @tparam T The type to deserialize into.
         * @param payload The byte vector to deserialize.
         * @return The deserialized data.
         */
        template<typename T>
        static T deserialize(const std::vector<std::byte>& payload) {
            T data;
            std::string str(reinterpret_cast<const char*>(payload.data()), payload.size());
            std::stringstream ss(str);
            boost::archive::binary_iarchive ia(ss);
            ia >> data;
            return data;
        }

    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive& ar, const unsigned int version) {
            ar & m_header.magic;
            ar & m_header.version;
            ar & m_header.type;
            ar & m_header.flags;
            ar & m_header.length;
            ar & m_header.nonce;
            ar & m_header.crc32;
            ar & m_payload;
        }

        ProtocolHeader m_header{};
        std::vector<std::byte> m_payload;
    };

} // namespace rgs::sdk::network
