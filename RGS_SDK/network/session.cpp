#include "network/session.hpp"
#include "network/protocol.hpp"
#include "network/session_manager.hpp"
#include "security/secure_clear.hpp"

#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/connect.hpp>
#include <cstring>

namespace rgs::sdk::network {

using boost::asio::buffer;
using boost::asio::async_read;
using boost::asio::async_write;
using boost::system::error_code;

Session::Session(boost::asio::io_context& io,
                 tcp::socket socket,
                 Dispatcher& dispatcher,
                 std::weak_ptr<SessionManager> manager,
                 std::function<std::optional<std::pair<std::vector<uint8_t>, std::string>>(const std::string&)> jwt_validator)
    : io_(io),
      socket_(std::move(socket)),
      dispatcher_(dispatcher),
      manager_(std::move(manager)),
      role_(SessionRole::ServerSide),
      jwt_validator_(std::move(jwt_validator)) {}

Session::Session(boost::asio::io_context& io,
                 Dispatcher& dispatcher,
                 const std::string& host, uint16_t port,
                 const std::string& jwt_token,
                 const std::vector<uint8_t>& ikm)
    : io_(io),
      socket_(io),
      dispatcher_(dispatcher),
      role_(SessionRole::ClientSide),
      jwt_validator_(nullptr),
      jwt_token_(jwt_token),
      client_ikm_(ikm) {
    client_handshake(host, port);
}

Session::~Session() {
    close();
}

void Session::start() {
    if (role_ == SessionRole::ServerSide) {
        server_handshake();
    } else {
        do_read_header();
    }
}

void Session::close() {
    error_code ec;
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

bool Session::send_plain(Message& msg) {
    if (!authenticated_ || aes_key_.size() != 32) return false;
    auto iv = iv_gen_.next_iv();
    if (!msg.encrypt(aes_key_, iv)) return false;
    write_encrypted(msg);
    return true;
}

bool Session::validate_nonce(const uint8_t* iv) {
    uint64_t ctr = 0;
    std::memcpy(&ctr, iv + 4, sizeof(uint64_t));
    uint64_t prev = last_iv_counter_.load(std::memory_order_relaxed);
    if (ctr <= prev) return false;
    last_iv_counter_.store(ctr, std::memory_order_relaxed);
    return true;
}

void Session::do_read_header() {
    auto self = shared_from_this();
    async_read(socket_, buffer(&incoming_header_, sizeof(PacketHeader)),
               [this, self](const error_code& ec, std::size_t) {
        if (ec) { close(); return; }
        if (incoming_header_.magic != MAGIC_VALUE) { close(); return; }
        do_read_body(static_cast<std::size_t>(incoming_header_.length));
    });
}

void Session::do_read_body(std::size_t body_len) {
    incoming_ciphertext_.resize(body_len);
    auto self = shared_from_this();
    async_read(socket_, buffer(incoming_ciphertext_.data(), incoming_ciphertext_.size()),
               [this, self](const error_code& ec, std::size_t) {
        if (ec) { close(); return; }

        // Reconstrói mensagem a partir do frame
        std::vector<uint8_t> frame(sizeof(PacketHeader) + incoming_ciphertext_.size());
        std::memcpy(frame.data(), &incoming_header_, sizeof(PacketHeader));
        if (!incoming_ciphertext_.empty()) {
            std::memcpy(frame.data() + sizeof(PacketHeader),
                        incoming_ciphertext_.data(), incoming_ciphertext_.size());
        }
        auto opt = Message::deserialize(frame.data(), frame.size());
        if (!opt) { close(); return; }
        incoming_msg_ = std::move(*opt);

        // Decriptação pós-handshake
        if (authenticated_) {
            if (!validate_nonce(incoming_msg_.header().iv)) { close(); return; }
            if (!incoming_msg_.decrypt(aes_key_)) { close(); return; }
        }
        process_incoming();
        do_read_header();
    });
}

void Session::process_incoming() {
    // Server-side handshake: recebe JWT
    if (!authenticated_ && role_ == SessionRole::ServerSide &&
        static_cast<MessageType>(incoming_msg_.header().type) == MessageType::HandshakeRequest) {

        std::string jwt(incoming_ciphertext_.begin(), incoming_ciphertext_.end());
        if (!jwt_validator_) { close(); return; }
        auto res = jwt_validator_(jwt);
        if (!res) { close(); return; }

        auto ikm = res->first;
        login_   = res->second;

        auto salt = rgs::sdk::security::Random::bytes(16);
        auto keys = rgs::sdk::security::HKDF::derive_session_keys(salt, ikm, "RGS/SESSION/v1");
        if (!keys) { close(); return; }

        aes_key_ = keys->enc_key;
        authenticated_ = true;

        // Registra sessão autenticada
        if (auto mgr = manager_.lock()) {
            mgr->on_authenticated(login_, shared_from_this());
        }

        // Responde HandshakeAccept com salt (sem criptografia)
        PacketHeader hdr{};
        hdr.magic = MAGIC_VALUE;
        hdr.type  = static_cast<uint32_t>(MessageType::HandshakeAccept);
        hdr.length = static_cast<uint32_t>(salt.size());
        std::memset(hdr.iv, 0, sizeof(hdr.iv));
        std::memset(hdr.tag, 0, sizeof(hdr.tag));

        std::vector<uint8_t> frame(sizeof(PacketHeader) + salt.size());
        std::memcpy(frame.data(), &hdr, sizeof(hdr));
        std::memcpy(frame.data() + sizeof(hdr), salt.data(), salt.size());

        auto self = shared_from_this();
        async_write(socket_, buffer(frame.data(), frame.size()),
                    [this, self, ikm = std::move(ikm), salt = std::move(salt)](const error_code& ec, std::size_t) {
            (void)ikm; (void)salt; // mantidos até completar write
            if (ec) { close(); return; }
            // Handshake concluído
        });
        return;
    }

    // Client-side handshake: recebe salt
    if (!authenticated_ && role_ == SessionRole::ClientSide &&
        static_cast<MessageType>(incoming_msg_.header().type) == MessageType::HandshakeAccept) {

        std::vector<uint8_t> salt(incoming_ciphertext_.begin(), incoming_ciphertext_.end());
        auto keys = rgs::sdk::security::HKDF::derive_session_keys(salt, client_ikm_, "RGS/SESSION/v1");
        if (!keys) { close(); return; }
        aes_key_ = keys->enc_key;
        authenticated_ = true;
        rgs::sdk::security::secure_clear(salt);
        return;
    }

    // Após handshake: roteamento normal
    dispatcher_.dispatch(incoming_msg_, *this);
}

void Session::server_handshake() {
    do_read_header();
}

void Session::client_handshake(const std::string& host, uint16_t port) {
    error_code ec;
    tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(host, std::to_string(port), ec);
    if (ec) { close(); return; }

    boost::asio::connect(socket_, endpoints, ec);
    if (ec) { close(); return; }

    // Envia HandshakeRequest com JWT (sem criptografia)
    std::vector<uint8_t> jwt(jwt_token_.begin(), jwt_token_.end());

    PacketHeader hdr{};
    hdr.magic = MAGIC_VALUE;
    hdr.type  = static_cast<uint32_t>(MessageType::HandshakeRequest);
    hdr.length = static_cast<uint32_t>(jwt.size());
    std::memset(hdr.iv, 0, sizeof(hdr.iv));
    std::memset(hdr.tag, 0, sizeof(hdr.tag));

    std::vector<uint8_t> frame(sizeof(PacketHeader) + jwt.size());
    std::memcpy(frame.data(), &hdr, sizeof(hdr));
    std::memcpy(frame.data() + sizeof(hdr), jwt.data(), jwt.size());

    async_write(socket_, buffer(frame.data(), frame.size()),
                [this](const error_code& ec, std::size_t) {
        if (ec) { close(); return; }
        do_read_header();
    });
}

void Session::write_encrypted(Message& msg) {
    auto data = msg.serialize();
    auto self = shared_from_this();
    async_write(socket_, buffer(data.data(), data.size()),
                [this, self](const error_code& ec, std::size_t) {
        if (ec) { close(); return; }
    });
}

} // namespace rgs::sdk::network
