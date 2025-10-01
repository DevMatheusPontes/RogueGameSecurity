#pragma once

#include <string>
#include <unordered_map>
#include <string_view>
#include <optional>
#include "security/secure_string.hpp"

namespace rgs::config {

// Config: carrega pares chave=valor de um arquivo simples.
// - Suporta comentários iniciados por '#'.
// - Armazena valores em mapa interno.
// - Para valores sensíveis, pode retornar SecureString.
class Config {
public:
    // Carrega de arquivo texto (UTF-8).
    bool load_from_file(const std::string& path);

    // Obtém valor como string (se existir).
    std::optional<std::string> get(std::string_view key) const;

    // Obtém valor como SecureString (para chaves sensíveis).
    std::optional<rgs::security::SecureString> get_secure(std::string_view key) const;

    // Define/atualiza valor.
    void set(std::string key, std::string value);

private:
    std::unordered_map<std::string, std::string> values_;
};

} // namespace rgs::config