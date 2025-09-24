#pragma once

#include <string>
#include <vector>
#include "protection_manager.hpp"

namespace rgs::sdk::protection {

enum class Severity {
    Info,
    Alert,
    Critical
};

struct ResponseRule {
    std::string modulo;
    std::string tipo;
    Severity    nivel;
    std::string acao; // "log", "neutralize", "terminate"
};

class ResponseEngine {
public:
    ResponseEngine();
    ~ResponseEngine();

    void add_rule(const ResponseRule& rule);
    void clear_rules();

    // Aplica resposta a um evento
    void handle_event(const ProtectionEvent& ev);

    // Aplica resposta a todos os eventos
    void handle_batch(const std::vector<ProtectionEvent>& eventos);

private:
    std::vector<ResponseRule> regras_;
};

} // namespace rgs::sdk::protection
