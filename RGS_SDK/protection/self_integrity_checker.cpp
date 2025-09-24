#include "self_integrity_checker.hpp"
#include <wincrypt.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

namespace rgs::sdk::protection {

SelfIntegrityChecker::SelfIntegrityChecker() = default;
SelfIntegrityChecker::~SelfIntegrityChecker() { shutdown(); }

bool SelfIntegrityChecker::initialize() {
    baseline_ = collect_sections();
    initialized_ = true;
    return true;
}

void SelfIntegrityChecker::shutdown() {
    stop_monitor();
    initialized_ = false;
    baseline_.clear();
    events_.clear();
}

void SelfIntegrityChecker::set_enable_monitor(bool enable) { monitor_enabled_ = enable; }
void SelfIntegrityChecker::set_poll_interval_ms(DWORD ms)  { poll_interval_ms_ = ms; }

bool SelfIntegrityChecker::start_monitor() {
    if (!initialized_ || !monitor_enabled_) return false;
    if (monitor_running_) return true;
    monitor_running_ = true;
    monitor_thread_ = std::thread(&SelfIntegrityChecker::monitor_loop, this);
    return true;
}

void SelfIntegrityChecker::stop_monitor() {
    if (!monitor_running_) return;
    monitor_running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

std::vector<IntegrityDetection> SelfIntegrityChecker::last_events() const {
    return events_;
}

std::string SelfIntegrityChecker::hash_memory(uintptr_t base, size_t size) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = sizeof(hash);

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return ""; }

    CryptHashData(hHash, reinterpret_cast<BYTE*>(base), static_cast<DWORD>(size), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    std::ostringstream oss;
    for (DWORD i=0;i<hashLen;i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}

std::vector<IntegritySection> SelfIntegrityChecker::collect_sections() {
    std::vector<IntegritySection> out;

    HMODULE self = GetModuleHandleA(nullptr);
    if (!self) return out;

    auto dos = (IMAGE_DOS_HEADER*)self;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)self + dos->e_lfanew);

    auto sec = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (UINT i=0;i<nt->FileHeader.NumberOfSections;i++) {
        char name[9]{};
        memcpy(name, sec[i].Name, 8);
        std::string sname(name);

        // Apenas seções críticas
        if (sname == ".text" || sname == ".rdata" || sname == ".data") {
            uintptr_t base = (uintptr_t)self + sec[i].VirtualAddress;
            size_t size    = sec[i].Misc.VirtualSize;
            std::string h  = hash_memory(base, size);

            out.push_back({ sname, base, size, h });
        }
    }
    return out;
}

std::vector<IntegrityDetection> SelfIntegrityChecker::scan_sections() {
    std::vector<IntegrityDetection> out;

    for (auto& b : baseline_) {
        std::string curHash = hash_memory(b.base, b.size);
        bool mod = (curHash != b.hash);

        IntegrityDetection d;
        d.section = b.name;
        d.description = mod ? "Hash divergente: seção modificada" : "Seção íntegra";
        d.isModified = mod;

        out.push_back(d);
    }

    events_ = out;
    return out;
}

bool SelfIntegrityChecker::detect_modifications() {
    auto res = scan_sections();
    return std::any_of(res.begin(), res.end(), [](auto& d){ return d.isModified; });
}

void SelfIntegrityChecker::monitor_loop() {
    while (monitor_running_) {
        auto res = scan_sections();
        for (auto& d : res) {
            if (d.isModified) {
                // Aqui você pode logar, reportar ou encerrar
            }
        }
        Sleep(poll_interval_ms_);
    }
}

} // namespace rgs::sdk::protection
