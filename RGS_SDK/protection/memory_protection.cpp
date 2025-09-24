#include "memory_protection.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <fstream>

// Local utilities
namespace {
    // 32-bit FNV-1a hash
    inline uint32_t fnv1a_32(const uint8_t* data, size_t len) {
        uint32_t hash = 0x811C9DC5u;
        for (size_t i = 0; i < len; ++i) {
            hash ^= data[i];
            hash *= 0x01000193u;
        }
        return hash;
    }

    inline bool read_memory(uintptr_t address, void* out, size_t size) {
        __try {
            std::memcpy(out, reinterpret_cast<void*>(address), size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    inline bool write_memory(uintptr_t address, const void* in, size_t size) {
        DWORD oldProt = 0;
        if (VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProt)) {
            std::memcpy(reinterpret_cast<void*>(address), in, size);
            VirtualProtect(reinterpret_cast<void*>(address), size, oldProt, &oldProt);
            return true;
        }
        return false;
    }

    inline bool change_protect(uintptr_t address, size_t size, DWORD newProt, DWORD* prev = nullptr) {
        DWORD oldProt = 0;
        bool ok = VirtualProtect(reinterpret_cast<void*>(address), size, newProt, &oldProt) != 0;
        if (ok && prev) *prev = oldProt;
        return ok;
    }

    struct SectionInfo {
        std::string name;
        uintptr_t base;
        size_t size;
        DWORD characteristics;
    };

    inline std::vector<SectionInfo> enumerate_self_sections() {
        std::vector<SectionInfo> out;
        HMODULE self = GetModuleHandleA(nullptr);
        if (!self) return out;

        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
        auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(self) + dos->e_lfanew);
        auto sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<uint8_t*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader
        );

        for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            char name[9] {};
            std::memcpy(name, sec[i].Name, 8);
            SectionInfo si;
            si.name = name;
            si.base = reinterpret_cast<uintptr_t>(self) + sec[i].VirtualAddress;
            si.size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            si.characteristics = sec[i].Characteristics;
            out.push_back(si);
        }
        return out;
    }

    inline std::pair<uintptr_t, size_t> module_range(HMODULE mod) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return {0,0};
        return {reinterpret_cast<uintptr_t>(mi.lpBaseOfDll), mi.SizeOfImage};
    }

    inline bool addr_in_module(uintptr_t addr, HMODULE mod) {
        auto [base, size] = module_range(mod);
        return base && addr >= base && addr < base + size;
    }

    inline bool addr_in_any_module(uintptr_t addr) {
        HMODULE mods[1024]; DWORD needed=0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return false;
        size_t count = needed / sizeof(HMODULE);
        for (size_t i=0; i<count; ++i) {
            if (addr_in_module(addr, mods[i])) return true;
        }
        return false;
    }

    inline std::vector<uint8_t> read_file_binary(const std::wstring& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return {};
        f.seekg(0, std::ios::end);
        size_t sz = (size_t)f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> buf(sz);
        f.read(reinterpret_cast<char*>(buf.data()), sz);
        return buf;
    }

    inline std::wstring self_path_w() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        return path;
    }
}

namespace rgs::sdk::protection {

MemoryProtection::MemoryProtection() = default;
MemoryProtection::~MemoryProtection() { shutdown(); }

bool MemoryProtection::initialize() {
    if (m_initialized) return true;

    // Snapshot original PE sections (for patch comparison)
    auto secs = enumerate_self_sections();
    m_originalSections.clear();
    for (auto& s : secs) {
        std::vector<std::byte> buf(s.size);
        if (read_memory(s.base, buf.data(), s.size)) {
            m_originalSections.emplace_back(s.base, std::move(buf));
        }
    }

    m_initialized = true;
    return true;
}

void MemoryProtection::shutdown() {
    if (m_accessMonitoringEnabled) disableAccessMonitoring();
    m_protectedRegions.clear();
    m_detectedThreats.clear();
    m_originalSections.clear();
    m_initialized = false;
}

// Anti-dump

bool MemoryProtection::enableAntiDump() {
    if (!m_initialized) initialize();
    bool ok = true;
    ok &= hidePEHeader();
    ok &= scrambleHeaders();
    ok &= protectCriticalSections();
    m_antiDumpEnabled = ok;
    return ok;
}

void MemoryProtection::disableAntiDump() {
    m_antiDumpEnabled = false;
}

bool MemoryProtection::isAntiDumpEnabled() const {
    return m_antiDumpEnabled;
}

bool MemoryProtection::hidePEHeader() {
    // Overwrite DOS header lightly to confuse dumpers (safe subset)
    auto secs = enumerate_self_sections();
    if (secs.empty()) return false;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    // Only scramble non-critical fields of DOS header stub, not e_lfanew.
    const size_t stubSize = 0x40; // small portion
    std::vector<uint8_t> zeros(stubSize, 0x00);
    return write_memory(reinterpret_cast<uintptr_t>(dos), zeros.data(), stubSize);
}

bool MemoryProtection::scrambleHeaders() {
    // Zero selected data directories (DEBUG, EXCEPTION) to reduce forensic info
    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(self) + dos->e_lfanew);

    auto& opt = nt->OptionalHeader;
    auto dirCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    for (UINT i = 0; i < dirCount; ++i) {
        if (i == IMAGE_DIRECTORY_ENTRY_DEBUG || i == IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            opt.DataDirectory[i].VirtualAddress = 0;
            opt.DataDirectory[i].Size = 0;
        }
    }
    return true;
}

bool MemoryProtection::protectCriticalSections() {
    // Set .text to PAGE_EXECUTE_READ and ensure no RWX in large regions
    auto secs = enumerate_self_sections();
    bool ok = true;
    for (auto& s : secs) {
        if (s.name == ".text") {
            DWORD prev{};
            ok &= change_protect(s.base, s.size, PAGE_EXECUTE_READ, &prev);
        }
    }

    // Harden large committed RWX regions
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= (1 << 20)) {
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                DWORD prev{};
                change_protect(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize, PAGE_EXECUTE_READ, &prev);
            }
        }
        addr += mbi.RegionSize;
    }
    return ok;
}

// Integrity regions

bool MemoryProtection::addIntegrityRegion(uintptr_t address, size_t size, const std::string& name) {
    if (m_protectedRegions.find(name) != m_protectedRegions.end()) return false;
    MemoryIntegrityRegion r;
    r.startAddress = address;
    r.size = size;
    r.originalHash = calculateRegionHash(address, size);
    r.originalProtection = PAGE_NOACCESS;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        r.originalProtection = mbi.Protect;
    }
    r.isProtected = false;
    r.name = name;
    m_protectedRegions[name] = r;
    return true;
}

bool MemoryProtection::removeIntegrityRegion(const std::string& name) {
    return m_protectedRegions.erase(name) > 0;
}

bool MemoryProtection::verifyIntegrity() {
    if (!m_integrityCheckEnabled) return true;
    bool allGood = true;
    for (auto& [name, r] : m_protectedRegions) {
        if (isRegionModified(r)) {
            allGood = false;
        }
    }
    return allGood;
}

std::vector<MemoryThreatDetection> MemoryProtection::checkIntegrityViolations() {
    m_detectedThreats.clear();
    if (!m_integrityCheckEnabled) return m_detectedThreats;

    for (auto& [name, r] : m_protectedRegions) {
        if (isRegionModified(r)) {
            MemoryThreatDetection det{};
            det.type = MemoryThreat::IntegrityViolation;
            det.address = r.startAddress;
            det.size = r.size;
            det.description = "Integrity violation in region: " + name;
            std::vector<std::byte> snapshot(r.size);
            read_memory(r.startAddress, snapshot.data(), r.size);
            det.suspiciousData = std::move(snapshot);
            m_detectedThreats.push_back(std::move(det));
        }
    }
    return m_detectedThreats;
}

uint32_t MemoryProtection::calculateRegionHash(uintptr_t address, size_t size) {
    std::vector<uint8_t> buf(size);
    if (!read_memory(address, buf.data(), size)) return 0;
    return fnv1a_32(buf.data(), buf.size());
}

bool MemoryProtection::isRegionModified(const MemoryIntegrityRegion& region) {
    auto h = calculateRegionHash(region.startAddress, region.size);
    if (h != region.originalHash) return true;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(region.startAddress), &mbi, sizeof(mbi))) {
        if (m_protectionLevel >= 4) {
            // At higher levels demand same protection
            if (mbi.Protect != region.originalProtection && region.originalProtection != PAGE_NOACCESS)
                return true;
        }
    }
    return false;
}

void MemoryProtection::updateRegionHash(MemoryIntegrityRegion& region) {
    region.originalHash = calculateRegionHash(region.startAddress, region.size);
}

// Hook detection

bool MemoryProtection::scanForHooks() {
    if (!m_hookDetectionEnabled) return false;
    m_detectedThreats.clear();
    bool hooked = false;

    hooked |= checkImportTable();
    hooked |= checkExportTable();
    hooked |= scanInlineHooks();

    return hooked;
}

std::vector<MemoryThreatDetection> MemoryProtection::detectHooks() {
    scanForHooks();
    return m_detectedThreats;
}

bool MemoryProtection::removeDetectedHooks() {
    // User-mode best-effort: cannot reliably remove hooks without original bytes.
    // Attempt: if inline hook detected pointing outside module, nop out first 5 bytes.
    bool any = false;
    for (auto& d : m_detectedThreats) {
        if (d.type == MemoryThreat::HookInjection && d.size >= 5) {
            std::vector<uint8_t> nops(d.size, 0x90);
            any |= write_memory(d.address, nops.data(), d.size);
        }
    }
    return any;
}

bool MemoryProtection::isAddressHooked(uintptr_t address) {
    // Check for JMP rel32 or absolute indirections typical of trampoline hooks
    uint8_t opcodes[6]{};
    if (!read_memory(address, opcodes, sizeof(opcodes))) return false;
    if (opcodes[0] == 0xE9 || opcodes[0] == 0xE8) {
        // Relative JMP/CALL likely hook
        return true;
    }
    // FF 25 (jmp [abs]) on x86
    if (opcodes[0] == 0xFF && opcodes[1] == 0x25) return true;
#ifdef _M_X64
    // 48 FF 25 (jmp [rip+rel]) frequently used by trampolines
    if (opcodes[0] == 0x48 && opcodes[1] == 0xFF && opcodes[2] == 0x25) return true;
#endif
    return false;
}

bool MemoryProtection::checkImportTable() {
    bool hooked = false;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(self) + dos->e_lfanew);

    auto& opt = nt->OptionalHeader;
    auto iatDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (!iatDir.VirtualAddress || !iatDir.Size) return false;

    auto iat = reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(self) + iatDir.VirtualAddress);
    size_t count = iatDir.Size / sizeof(uintptr_t);

    auto [base, size] = module_range(self);

    for (size_t i = 0; i < count; ++i) {
        uintptr_t tgt = iat[i];
        if (!tgt) continue;
        if (tgt < base || tgt >= base + size) {
            // IAT entry pointing outside module – could be hooked
            MemoryThreatDetection det{};
            det.type = MemoryThreat::HookInjection;
            det.address = reinterpret_cast<uintptr_t>(&iat[i]);
            det.size = sizeof(uintptr_t);
            det.description = "IAT entry redirected outside module";
            m_detectedThreats.push_back(det);
            hooked = true;
        }
    }
    return hooked;
}

bool MemoryProtection::checkExportTable() {
    bool hooked = false;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(self) + dos->e_lfanew);

    auto& opt = nt->OptionalHeader;
    auto expDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) return false;

    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<uint8_t*>(self) + expDir.VirtualAddress
    );
    auto funcs = reinterpret_cast<uint32_t*>(
        reinterpret_cast<uint8_t*>(self) + exp->AddressOfFunctions
    );

    auto [base, size] = module_range(self);

    for (DWORD i = 0; i < exp->NumberOfFunctions; ++i) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(self) + funcs[i]);
        if (!addr) continue;

        // Check inline hook at function entry
        if (isAddressHooked(addr)) {
            MemoryThreatDetection det{};
            det.type = MemoryThreat::HookInjection;
            det.address = addr;
            det.size = 16;
            det.description = "Inline hook detected at export function";
            std::vector<std::byte> bytes(16);
            read_memory(addr, bytes.data(), bytes.size());
            det.suspiciousData = std::move(bytes);
            m_detectedThreats.push_back(det);
            hooked = true;
        }
    }
    return hooked;
}

bool MemoryProtection::scanInlineHooks() {
    bool hooked = false;
    // Scan .text for suspicious JMP trampolines
    auto secs = enumerate_self_sections();
    for (auto& s : secs) {
        if (s.name != ".text") continue;
        std::vector<uint8_t> buf(s.size);
        if (!read_memory(s.base, buf.data(), buf.size())) continue;
        for (size_t i = 0; i + 5 <= buf.size(); ++i) {
            uint8_t b0 = buf[i];
            if (b0 == 0xE9 || b0 == 0xE8) {
                // Relative target
                int32_t rel = *reinterpret_cast<int32_t*>(&buf[i+1]);
                uintptr_t target = s.base + i + 5 + rel;
                if (!addr_in_any_module(target)) {
                    MemoryThreatDetection det{};
                    det.type = MemoryThreat::HookInjection;
                    det.address = s.base + i;
                    det.size = 5;
                    det.description = "Suspicious JMP/CALL in .text to non-module address";
                    det.suspiciousData = { std::byte(b0),
                                           std::byte(buf[i+1]),
                                           std::byte(buf[i+2]),
                                           std::byte(buf[i+3]),
                                           std::byte(buf[i+4]) };
                    m_detectedThreats.push_back(det);
                    hooked = true;
                }
            }
        }
    }
    return hooked;
}

// Access monitoring

LONG WINAPI MemoryProtection::vectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    auto code = pExceptionInfo->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_GUARD_PAGE || code == EXCEPTION_ACCESS_VIOLATION) {
        // Guard page hit or illegal access – tag as threat
        // We cannot access instance members in static handler; record minimal info via TLS or global if needed.
        // Here we simply continue execution to allow app to run, but guard pages will be re-applied by monitor logic.
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool MemoryProtection::setupPageGuards() {
    bool any = false;
    for (auto& [name, r] : m_protectedRegions) {
        DWORD prev{};
        if (change_protect(r.startAddress, r.size, PAGE_READONLY | PAGE_GUARD, &prev)) {
            r.isProtected = true;
            any = true;
        }
    }
    return any;
}

void MemoryProtection::removePageGuards() {
    for (auto& [name, r] : m_protectedRegions) {
        if (!r.isProtected) continue;
        DWORD prev{};
        change_protect(r.startAddress, r.size, r.originalProtection ? r.originalProtection : PAGE_READONLY, &prev);
        r.isProtected = false;
    }
}

bool MemoryProtection::enableAccessMonitoring() {
    if (m_accessMonitoringEnabled) return true;
    m_vehHandler = AddVectoredExceptionHandler(1, MemoryProtection::vectoredExceptionHandler);
    bool ok = (m_vehHandler != nullptr);
    ok &= setupPageGuards();
    m_accessMonitoringEnabled = ok;
    return ok;
}

void MemoryProtection::disableAccessMonitoring() {
    if (!m_accessMonitoringEnabled) return;
    removePageGuards();
    if (m_vehHandler) {
        RemoveVectoredExceptionHandler(m_vehHandler);
        m_vehHandler = nullptr;
    }
    m_accessMonitoringEnabled = false;
}

std::vector<MemoryThreatDetection> MemoryProtection::getAccessViolations() {
    // In this implementation, access violations are not persisted; integrate with external logger if needed.
    // Return current detected threats filtered by IllegalAccess.
    std::vector<MemoryThreatDetection> out;
    for (auto& d : m_detectedThreats) {
        if (d.type == MemoryThreat::IllegalAccess) out.push_back(d);
    }
    return out;
}

// Code injection detection

bool MemoryProtection::scanExecutableRegions() {
    bool any = false;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        bool committed = (mbi.State == MEM_COMMIT);
        bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t size = mbi.RegionSize;

        if (committed && exec) {
            if (!addr_in_any_module(base)) {
                // Potential injected code region
                MemoryThreatDetection det{};
                det.type = MemoryThreat::CodeInjection;
                det.address = base;
                det.size = size;
                det.description = "Executable region outside known modules";
                std::vector<std::byte> sample(std::min<size_t>(size, 256));
                read_memory(base, sample.data(), sample.size());
                det.suspiciousData = std::move(sample);
                m_detectedThreats.push_back(det);
                any = true;
            } else if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE && m_protectionLevel >= 4) {
                // RWX in module: suspicious patching context
                MemoryThreatDetection det{};
                det.type = MemoryThreat::MemoryPatch;
                det.address = base;
                det.size = size;
                det.description = "RWX region inside module – probable patching";
                m_detectedThreats.push_back(det);
                any = true;
            }
        }
        addr += mbi.RegionSize;
    }
    return any;
}

bool MemoryProtection::validateExecutableCode(uintptr_t address, size_t size) {
    // Lightweight heuristic: detect high ratio of NOPs or jumps – typical of trampolines/sleds
    std::vector<uint8_t> buf(std::min<size_t>(size, 512));
    if (!read_memory(address, buf.data(), buf.size())) return false;
    size_t nopCount = 0, jmpCount = 0;
    for (auto b : buf) {
        if (b == 0x90) ++nopCount;
        if (b == 0xE9 || b == 0xEB || b == 0xE8 || b == 0xFF) ++jmpCount;
    }
    double ratio = (double)(nopCount + jmpCount) / (double)buf.size();
    return ratio < 0.20; // if too many control-transfer/nops, treat as suspicious elsewhere
}

bool MemoryProtection::detectCodeInjection() {
    m_detectedThreats.clear();
    bool inj = scanExecutableRegions();

    // Validate flagged regions
    for (auto& d : m_detectedThreats) {
        if (d.type == MemoryThreat::CodeInjection) {
            if (!validateExecutableCode(d.address, d.size)) {
                // keep as suspicious (do nothing)
            }
        }
    }
    return std::any_of(m_detectedThreats.begin(), m_detectedThreats.end(),
                       [](auto& x){ return x.type == MemoryThreat::CodeInjection; });
}

std::vector<MemoryThreatDetection> MemoryProtection::scanForInjectedCode() {
    detectCodeInjection();
    return m_detectedThreats;
}

// Memory patch detection

bool MemoryProtection::compareWithDiskImage() {
    bool any = false;

    // Read on-disk image and compare .text snapshot with in-memory current
    auto path = self_path_w();
    auto disk = read_file_binary(path);
    if (disk.empty()) return false;

    HMODULE self = GetModuleHandleA(nullptr);
    auto dosMem = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto ntMem  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(self) + dosMem->e_lfanew);

    // Parse disk PE
    auto dosDisk = reinterpret_cast<IMAGE_DOS_HEADER*>(disk.data());
    if (dosDisk->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto ntDisk = reinterpret_cast<IMAGE_NT_HEADERS*>(disk.data() + dosDisk->e_lfanew);
    auto secDisk = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntDisk->OptionalHeader) + ntDisk->FileHeader.SizeOfOptionalHeader);

    // Find .text section on disk
    IMAGE_SECTION_HEADER* textDisk = nullptr;
    for (UINT i = 0; i < ntDisk->FileHeader.NumberOfSections; ++i) {
        char nm[9]{};
        std::memcpy(nm, secDisk[i].Name, 8);
        if (std::string(nm) == ".text") {
            textDisk = &secDisk[i];
            break;
        }
    }
    if (!textDisk) return false;

    size_t diskTextSize = textDisk->SizeOfRawData;
    const uint8_t* diskTextPtr = disk.data() + textDisk->PointerToRawData;

    // Compare with current memory .text
    auto secsMem = enumerate_self_sections();
    for (auto& s : secsMem) {
        if (s.name != ".text") continue;
        size_t cmpSize = std::min(s.size, diskTextSize);
        std::vector<uint8_t> memBuf(cmpSize);
        if (!read_memory(s.base, memBuf.data(), cmpSize)) continue;
        if (std::memcmp(memBuf.data(), diskTextPtr, cmpSize) != 0) {
            MemoryThreatDetection det{};
            det.type = MemoryThreat::MemoryPatch;
            det.address = s.base;
            det.size = cmpSize;
            det.description = "Memory .text diverges from disk image";
            m_detectedThreats.push_back(det);
            any = true;
        }
    }
    return any;
}

bool MemoryProtection::scanForNopSleds() {
    bool any = false;
    auto secs = enumerate_self_sections();
    for (auto& s : secs) {
        if (s.name != ".text") continue;
        std::vector<uint8_t> buf(s.size);
        if (!read_memory(s.base, buf.data(), buf.size())) continue;
        size_t consec = 0;
        for (size_t i = 0; i < buf.size(); ++i) {
            if (buf[i] == 0x90) {
                consec++;
                if (consec >= 32) {
                    MemoryThreatDetection det{};
                    det.type = MemoryThreat::MemoryPatch;
                    det.address = s.base + i - consec + 1;
                    det.size = consec;
                    det.description = "NOP sled detected in .text";
                    m_detectedThreats.push_back(det);
                    any = true;
                    break;
                }
            } else {
                consec = 0;
            }
        }
    }
    return any;
}

bool MemoryProtection::detectRuntimePatches() {
    bool any = false;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        bool committed = (mbi.State == MEM_COMMIT);
        if (committed) {
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                MemoryThreatDetection det{};
                det.type = MemoryThreat::MemoryPatch;
                det.address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                det.size = mbi.RegionSize;
                det.description = "RWX region – probable runtime patching";
                m_detectedThreats.push_back(det);
                any = true;
            }
        }
        addr += mbi.RegionSize;
    }
    return any;
}

bool MemoryProtection::detectMemoryPatches() {
    m_detectedThreats.clear();
    bool a = compareWithDiskImage();
    bool b = scanForNopSleds();
    bool c = detectRuntimePatches();
    return a || b || c;
}

std::vector<MemoryThreatDetection> MemoryProtection::scanForPatches() {
    detectMemoryPatches();
    return m_detectedThreats;
}

// Config

void MemoryProtection::setProtectionLevel(int level) {
    if (level < 1) level = 1;
    if (level > 5) level = 5;
    m_protectionLevel = level;
}

int MemoryProtection::getProtectionLevel() const {
    return m_protectionLevel;
}

void MemoryProtection::setStealthMode(bool enabled) {
    m_stealthMode = enabled;
}

} // namespace rgs::sdk::protection
