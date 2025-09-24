#pragma once

#include <string>
#include <unordered_map>
#include <optional>
#include <vector>
#include <cstdint>

namespace rgs::sdk::security {

struct Jwt {
    std::string token;
};

class JwtHS256 {
public:
    // claims: mapa simples de chave/valor, ex: {"sub":"user123","role":"client"}
    static std::optional<Jwt> sign(const std::unordered_map<std::string, std::string>& claims,
                                   const std::vector<uint8_t>& key,
                                   uint64_t exp_epoch_seconds = 0);

    static std::optional<std::unordered_map<std::string, std::string>>
    verify(const std::string& token, const std::vector<uint8_t>& key);

private:
    static std::string base64url_encode(const std::string& in);
    static std::optional<std::string> base64url_decode(const std::string& in);
    static std::string json_encode(const std::unordered_map<std::string, std::string>& obj);
    static std::optional<std::unordered_map<std::string, std::string>> json_decode(const std::string& json);
};

} // namespace rgs::sdk::security
