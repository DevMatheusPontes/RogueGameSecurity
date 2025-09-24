#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace rgs::sdk::protection {

struct HookEvent {
    std::string tipo;          // "IAT", "EAT", "Inline"
    std::string descricao;     // Texto explicativo
    uintptr_t   endereco;      // Endereço da evidência (entrada IAT/EAT ou início da função)
    uintptr_t   destino;       // Endereço de destino do desvio (se aplicável)
    size_t      tamanho;       // Tamanho analisado (bytes)
    bool        suspeito;      // Sinaliza detecção
};

class AntiHook {
public:
    AntiHook();
    ~AntiHook();

    bool initialize();
    void shutdown();

    // Varreduras
    std::vector<HookEvent> scan_iat();
    std::vector<HookEvent> scan_eat();
    std::vector<HookEvent> scan_inline();

    // Agregado
    std::vector<HookEvent> scan_all();
    bool detect_hooks();

    // Últimos eventos
    std::vector<HookEvent> last_events() const;

    // Neutralização (melhor esforço)
    // - IAT: restaura ponteiro para dentro do módulo principal
    // - Inline: NOP nos primeiros bytes do salto (se certeza alta)
    // Observação: EAT é arriscado modificar; apenas reportamos.
    bool neutralize_iat();
    bool neutralize_inline();

private:
    // Helpers PE
    struct SectionInfo {
        std::string nome;
        uintptr_t   base;
        size_t      tamanho;
    };

    std::vector<SectionInfo> enumerate_self_sections() const;
    std::pair<uintptr_t, size_t> module_range(HMODULE mod) const;
    bool addr_in_module(uintptr_t addr, HMODULE mod) const;
    bool addr_in_any_module(uintptr_t addr) const;

    // Leitura/Escrita segura
    bool read_mem(uintptr_t addr, void* out, size_t len) const;
    bool write_mem(uintptr_t addr, const void* in, size_t len) const;

    // Inline hook heurística
    bool looks_like_trampoline(uint8_t* p, size_t n, uintptr_t& targetOut) const;

private:
    bool initialized_{false};
    std::vector<HookEvent> eventos_;
};

} // namespace rgs::sdk::protection
