#include "response_engine.hpp"
#include <iostream>
#include <windows.h>

namespace rgs::sdk::protection {

ResponseEngine::ResponseEngine() = default;
ResponseEngine::~ResponseEngine() = default;

void ResponseEngine::add_rule(const ResponseRule& rule) {
    regras_.push_back(rule);
}

void ResponseEngine::clear_rules() {
    regras_.clear();
}

void ResponseEngine::handle_event(const ProtectionEvent& ev) {
    // Procura regra correspondente
    for (auto& r : regras_) {
        if (r.modulo == ev.modulo && r.tipo == ev.tipo) {
            switch (r.nivel) {
                case Severity::Info:
                    std::cout << "[INFO] " << ev.modulo << " :: " << ev.descricao << "\n";
                    break;
                case Severity::Alert:
                    std::cout << "[ALERTA] " << ev.modulo << " :: " << ev.descricao
                              << " -> Ação: " << r.acao << "\n";
                    // Aqui poderíamos chamar neutralizadores específicos
                    break;
                case Severity::Critical:
                    std::cerr << "[CRÍTICO] " << ev.modulo << " :: " << ev.descricao
                              << " -> Encerrando processo!\n";
                    ExitProcess(0);
                    break;
            }
            return;
        }
    }

    // Se não houver regra, loga como padrão
    std::cout << "[EVENTO] " << ev.modulo << " :: " << ev.descricao << "\n";
}

void ResponseEngine::handle_batch(const std::vector<ProtectionEvent>& eventos) {
    for (auto& ev : eventos) {
        handle_event(ev);
    }
}

} // namespace rgs::sdk::protection
