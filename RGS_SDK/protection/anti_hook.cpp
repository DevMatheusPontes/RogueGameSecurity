#include "anti_hook.hpp"
#include <psapi.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>

namespace rgs::sdk::protection {

AntiHook::AntiHook() = default;
AntiHook::~AntiHook() { shutdown(); }

bool AntiHook::initialize() {
    initialized_ = true;
    return true;
}

void AntiHook::shutdown() {
    initialized_ = false;
    eventos_.clear();
}

std::vector<AntiHook::SectionInfo> AntiHook::enumerate_self_sections() const {
    std::vector<SectionInfo> out;
    HMODULE self = GetModuleHandleA(nullptr);
    if (!self) return out;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>((uint8_t*)self + dos->e_lfanew);
    auto sec = reinterpret_cast<IMAGE_SECTION_HEADER*>((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char name[9]{};
        std::memcpy(name, sec[i].Name, 8);
        SectionInfo si;
        si.nome = name;
        si.base = (uintptr_t)self + sec[i].VirtualAddress;
        si.tamanho = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        out.push_back(si);
    }
    return out;
}

std::pair<uintptr_t, size_t> AntiHook::module_range(HMODULE mod) const {
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return {0,0};
    return { (uintptr_t)mi.lpBaseOfDll, (size_t)mi.SizeOfImage };
}

bool AntiHook::addr_in_module(uintptr_t addr, HMODULE mod) const {
    auto [base, size] = module_range(mod);
    return base && addr >= base && addr < base + size;
}

bool AntiHook::addr_in_any_module(uintptr_t addr) const {
    HMODULE mods[1024]; DWORD needed{};
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return false;
    size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        if (addr_in_module(addr, mods[i])) return true;
    }
    return false;
}

bool AntiHook::read_mem(uintptr_t addr, void* out, size_t len) const {
    __try {
        std::memcpy(out, (void*)addr, len);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool AntiHook::write_mem(uintptr_t addr, const void* in, size_t len) const {
    DWORD old{};
    if (!VirtualProtect((void*)addr, len, PAGE_EXECUTE_READWRITE, &old)) return false;
    std::memcpy((void*)addr, in, len);
    VirtualProtect((void*)addr, len, old, &old);
    return true;
}

bool AntiHook::looks_like_trampoline(uint8_t* p, size_t n, uintptr_t& targetOut) const {
    if (n < 5) return false;
    // JMP rel32
    if (p[0] == 0xE9) {
        int32_t rel = *(int32_t*)&p[1];
        targetOut = (uintptr_t)p + 5 + rel;
        return true;
    }
    // CALL rel32 (menos comum em trampolim, mas válido para desvio)
    if (p[0] == 0xE8) {
        int32_t rel = *(int32_t*)&p[1];
        targetOut = (uintptr_t)p + 5 + rel;
        return true;
    }
    // x86: FF 25 [abs]
    if (n >= 6 && p[0] == 0xFF && p[1] == 0x25) {
        uintptr_t ptr = *(uintptr_t*)&p[2];
        targetOut = *(uintptr_t*)ptr;
        return true;
    }
#ifdef _M_X64
    // x64: 48 FF 25 rel32 => jmp [rip+rel]
    if (n >= 6 && p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) {
        int32_t rel = *(int32_t*)&p[3];
        uintptr_t ripRef = (uintptr_t)p + 7 + rel;
        targetOut = *(uintptr_t*)ripRef;
        return true;
    }
#endif
    return false;
}

// ———————————————— IAT ————————————————

std::vector<HookEvent> AntiHook::scan_iat() {
    std::vector<HookEvent> out;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)self;
    auto nt  = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);
    auto& opt = nt->OptionalHeader;

    auto iatDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (!iatDir.VirtualAddress || !iatDir.Size) {
        eventos_.clear();
        return out;
    }

    auto iat = (uintptr_t*)((uint8_t*)self + iatDir.VirtualAddress);
    size_t count = iatDir.Size / sizeof(uintptr_t);

    auto [base, size] = module_range(self);

    for (size_t i = 0; i < count; ++i) {
        uintptr_t tgt = iat[i];
        if (!tgt) continue;

        bool interno = (tgt >= base && tgt < base + size);
        if (!interno) {
            HookEvent ev{};
            ev.tipo = "IAT";
            ev.descricao = "Entrada IAT aponta fora do módulo principal";
            ev.endereco = (uintptr_t)&iat[i];
            ev.destino  = tgt;
            ev.tamanho = sizeof(uintptr_t);
            ev.suspeito = true;
            out.push_back(ev);
        }
    }

    eventos_ = out;
    return out;
}

bool AntiHook::neutralize_iat() {
    bool any = false;
    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)self;
    auto nt  = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);
    auto& opt = nt->OptionalHeader;

    auto iatDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (!iatDir.VirtualAddress || !iatDir.Size) return false;

    auto iat = (uintptr_t*)((uint8_t*)self + iatDir.VirtualAddress);
    size_t count = iatDir.Size / sizeof(uintptr_t);
    auto [base, size] = module_range(self);

    for (size_t i = 0; i < count; ++i) {
        uintptr_t* entry = &iat[i];
        uintptr_t tgt = iat[i];
        if (!tgt) continue;

        bool interno = (tgt >= base && tgt < base + size);
        if (!interno) {
            // Melhor esforço: se o import for originalmente resolvido dentro de K32/NTDLL, mantemos.
            // Caso contrário, redefine para 0 para quebrar o hook (arriscado; preferível apenas reportar).
            // Aqui optamos por reportar e não alterar agressivamente. Retorne false para não aplicar mudanças.
            // Se quiser, substitua por write_mem((uintptr_t)entry, &baseAlgum, sizeof(uintptr_t));
            any = true;
        }
    }
    return any;
}

// ———————————————— EAT ————————————————

std::vector<HookEvent> AntiHook::scan_eat() {
    std::vector<HookEvent> out;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)self;
    auto nt  = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);

    auto& opt = nt->OptionalHeader;
    auto expDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) {
        eventos_.clear();
        return out;
    }

    auto exp = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)self + expDir.VirtualAddress);
    auto funcs = (uint32_t*)((uint8_t*)self + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfFunctions; ++i) {
        uintptr_t fn = (uintptr_t)((uint8_t*)self + funcs[i]);
        if (!fn) continue;

        uint8_t first[8]{};
        if (!read_mem(fn, first, sizeof(first))) continue;

        uintptr_t target{};
        if (looks_like_trampoline(first, sizeof(first), target)) {
            HookEvent ev{};
            ev.tipo = "EAT";
            ev.descricao = "Função exportada com prólogo de desvio (potencial hook)";
            ev.endereco = fn;
            ev.destino  = target;
            ev.tamanho = 8;
            ev.suspeito = true;
            out.push_back(ev);
        }
    }

    eventos_ = out;
    return out;
}

// ———————————————— Inline ————————————————

std::vector<HookEvent> AntiHook::scan_inline() {
    std::vector<HookEvent> out;

    auto secs = enumerate_self_sections();
    for (auto& s : secs) {
        if (s.nome != ".text") continue;
        // Percorre blocos da .text procurando trampolines
        size_t step = 1;
        for (size_t off = 0; off + 8 <= s.tamanho; off += step) {
            uint8_t buf[8]{};
            if (!read_mem(s.base + off, buf, sizeof(buf))) continue;
            uintptr_t target{};
            if (looks_like_trampoline(buf, sizeof(buf), target)) {
                // Se destino está fora de módulos conhecidos, forte indício de hook
                bool externo = !addr_in_any_module(target);
                HookEvent ev{};
                ev.tipo = "Inline";
                ev.descricao = externo ? "Desvio inline para endereço fora de módulos" : "Desvio inline para outro módulo";
                ev.endereco = s.base + off;
                ev.destino  = target;
                ev.tamanho = 5; // tamanho mínimo de JMP rel32
                ev.suspeito = true;
                out.push_back(ev);
                // Para evitar floods, avance alguns bytes
                step = 5;
            } else {
                step = 1;
            }
        }
    }

    eventos_ = out;
    return out;
}

std::vector<HookEvent> AntiHook::scan_all() {
    std::vector<HookEvent> out;
    auto i = scan_iat();   out.insert(out.end(), i.begin(), i.end());
    auto e = scan_eat();   out.insert(out.end(), e.begin(), e.end());
    auto inl = scan_inline(); out.insert(out.end(), inl.begin(), inl.end());
    eventos_ = out;
    return out;
}

bool AntiHook::detect_hooks() {
    auto all = scan_all();
    return std::any_of(all.begin(), all.end(), [](const HookEvent& ev){ return ev.suspeito; });
}

std::vector<HookEvent> AntiHook::last_events() const {
    return eventos_;
}

bool AntiHook::neutralize_inline() {
    bool any = false;
    for (const auto& ev : eventos_) {
        if (ev.tipo == "Inline" && ev.suspeito) {
            // NOP out primeiros 5 bytes (apenas se certeza alta de JMP rel32)
            uint8_t op[5]{};
            if (!read_mem(ev.endereco, op, sizeof(op))) continue;
            if (op[0] == 0xE9 || op[0] == 0xE8) {
                std::vector<uint8_t> nops(5, 0x90);
                if (write_mem(ev.endereco, nops.data(), nops.size())) {
                    any = true;
                }
            }
        }
    }
    return any;
}

} // namespace rgs::sdk::protection
