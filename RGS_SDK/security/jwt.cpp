#include "jwt.hpp"
#include "hmac.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>

namespace rgs::sdk::security {

static std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.length(), to);
        pos += to.length();
    }
    return s;
}

// Minimal base64url encode/decode (sem padding '=')
std::string JwtHS256::base64url_encode(const std::string& in) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
    out = replace_all(out, "+", "-");
    out = replace_all(out, "/", "_");
    // remove padding '='
    return out;
}

std::optional<std::string> JwtHS256::base64url_decode(const std::string& in_) {
    std::string in = replace_all(replace_all(in_, "-", "+"), "_", "/");
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (uint8_t c : in) {
        if (T[c] == -1) return std::nullopt;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Minimal JSON encode/decode para mapas simples de string->string (sem aninhamento)
std::string JwtHS256::json_encode(const std::unordered_map<std::string, std::string>& obj) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& [k, v] : obj) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << k << "\":\"" << v << "\"";
    }
    oss << "}";
    return oss.str();
}

// Decoder trivial: espera valores sem caracteres especiais
std::optional<std::unordered_map<std::string, std::string>> JwtHS256::json_decode(const std::string& json) {
    std::unordered_map<std::string, std::string> out;
    size_t i = 0;
    auto skip = [&](char c){ while (i < json.size() && json[i] == c) ++i; };
    skip(' ');
    if (i >= json.size() || json[i] != '{') return std::nullopt;
    ++i;
    while (i < json.size()) {
        while (i < json.size() && (json[i] == ' ' || json[i] == ',')) ++i;
        if (i < json.size() && json[i] == '}') { ++i; break; }
        if (json[i] != '"') return std::nullopt;
        size_t k1 = ++i, k2 = json.find('"', k1);
        if (k2 == std::string::npos) return std::nullopt;
        std::string key = json.substr(k1, k2 - k1);
        i = k2 + 1;
        while (i < json.size() && (json[i] == ' ' || json[i] == ':')) ++i;
        if (json[i] != '"') return std::nullopt;
        size_t v1 = ++i, v2 = json.find('"', v1);
        if (v2 == std::string::npos) return std::nullopt;
        std::string val = json.substr(v1, v2 - v1);
        i = v2 + 1;
        out[key] = val;
    }
    return out;
}

std::optional<Jwt> JwtHS256::sign(const std::unordered_map<std::string, std::string>& claims,
                                  const std::vector<uint8_t>& key,
                                  uint64_t exp_epoch_seconds) {
    // Header
    std::unordered_map<std::string, std::string> header = { {"alg","HS256"}, {"typ","JWT"} };
    std::string header_json = json_encode(header);
    std::string header_b64 = base64url_encode(header_json);

    // Claims (+ exp opcional)
    auto c = claims;
    if (exp_epoch_seconds != 0) {
        c["exp"] = std::to_string(exp_epoch_seconds);
    }
    std::string claims_json = json_encode(c);
    std::string claims_b64 = base64url_encode(claims_json);

    std::string signing_input = header_b64 + "." + claims_b64;

    auto mac = Hmac::sha256(key, std::vector<uint8_t>(signing_input.begin(), signing_input.end()));
    std::string signature_b64 = base64url_encode(std::string(mac.begin(), mac.end()));

    Jwt out { signing_input + "." + signature_b64 };
    return out;
}

std::optional<std::unordered_map<std::string, std::string>>
JwtHS256::verify(const std::string& token, const std::vector<uint8_t>& key) {
    auto p1 = token.find('.');
    if (p1 == std::string::npos) return std::nullopt;
    auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string::npos) return std::nullopt;

    std::string header_b64 = token.substr(0, p1);
    std::string claims_b64 = token.substr(p1 + 1, p2 - (p1 + 1));
    std::string sig_b64 = token.substr(p2 + 1);

    auto header_json = base64url_decode(header_b64);
    auto claims_json = base64url_decode(claims_b64);
    auto sig = base64url_decode(sig_b64);
    if (!header_json || !claims_json || !sig) return std::nullopt;

    // Recalcula MAC e compara
    std::string signing_input = header_b64 + "." + claims_b64;
    auto mac = Hmac::sha256(key, std::vector<uint8_t>(signing_input.begin(), signing_input.end()));

    if (mac.size() != sig->size() || !std::equal(mac.begin(), mac.end(), sig->begin())) {
        return std::nullopt;
    }

    auto claims = json_decode(*claims_json);
    if (!claims) return std::nullopt;

    // Verifica exp, se presente
    auto it = claims->find("exp");
    if (it != claims->end()) {
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t exp = std::strtoull(it->second.c_str(), nullptr, 10);
        if (exp && now > exp) return std::nullopt;
    }

    return claims;
}

} // namespace rgs::sdk::security
