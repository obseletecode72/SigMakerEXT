#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <regex>
#include <algorithm>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include "hde64.h"

static constexpr size_t DEFAULT_MAX_SIG_LEN = 50;
static constexpr size_t DEFAULT_MAX_PRINT_OCC = 50;

enum class SigFormat { IDA = 1, X64dbg, CByteArrayMask, CRawBytesBitmask };

struct SigByte { uint8_t value; bool wildcard; };

static std::vector<std::string> SplitTokens(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

std::vector<SigByte> ParseSignature(const std::string& input) {
    std::vector<SigByte> sig;
    std::smatch m;
    static const std::regex re_bytearray(R"((\\x[0-9A-Fa-f]{2}))");
    auto parts = SplitTokens(input);
    if (parts.size() == 2 && parts[0].find("\\x") != std::string::npos) {
        const auto& bytes = parts[0];
        const auto& mask = parts[1];
        auto it = std::sregex_iterator(bytes.begin(), bytes.end(), re_bytearray);
        auto end = std::sregex_iterator();
        size_t idx = 0;
        for (; it != end; ++it, ++idx) {
            uint8_t val = static_cast<uint8_t>(std::stoul((*it).str().substr(2), nullptr, 16));
            bool wc = idx < mask.size() && mask[idx] == '?';
            sig.push_back({ val, wc });
        }
        return sig;
    }
    static const std::regex re_rawbyte(R"(0x([0-9A-Fa-f]{2}))");
    if (input.find("0b") != std::string::npos) {
        auto pos = input.find("0b");
        std::string bytesPart = input.substr(0, pos);
        std::string bits = input.substr(pos + 2);
        auto it = std::sregex_iterator(bytesPart.begin(), bytesPart.end(), re_rawbyte);
        auto end = std::sregex_iterator();
        std::vector<uint8_t> vals;
        for (; it != end; ++it)
            vals.push_back(static_cast<uint8_t>(std::stoul((*it)[1], nullptr, 16)));
        for (size_t i = 0; i < vals.size(); ++i) {
            bool wc = (i < bits.size() && bits[bits.size() - 1 - i] == '0');
            sig.push_back({ vals[i], wc });
        }
        return sig;
    }
    for (const auto& t : SplitTokens(input)) {
        if (t == "?" || t == "??")
            sig.push_back({ 0, true });
        else
            sig.push_back({ static_cast<uint8_t>(std::stoul(t, nullptr, 16)), false });
    }
    return sig;
}

std::vector<uint8_t> ReadModuleBytes(HANDLE hProc, void* addr, void** outBase, size_t* outSize) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)))
        throw std::runtime_error("VirtualQueryEx failed");
    auto base = static_cast<uint8_t*>(mbi.AllocationBase);
    size_t total = 0;
    uint8_t* ptr = base;
    while (true) {
        if (!VirtualQueryEx(hProc, ptr, &mbi, sizeof(mbi))) break;
        if (mbi.AllocationBase != base) break;
        if (mbi.State == MEM_COMMIT) total += mbi.RegionSize;
        ptr += mbi.RegionSize;
    }
    std::vector<uint8_t> buf(total);
    SIZE_T rd;
    if (!ReadProcessMemory(hProc, base, buf.data(), total, &rd))
        throw std::runtime_error("ReadProcessMemory failed");
    *outBase = base;
    *outSize = static_cast<size_t>(rd);
    return buf;
}

size_t CountOccurrences(const std::vector<uint8_t>& buf, const std::vector<SigByte>& sig, size_t maxPrint) {
    size_t count = 0, bsz = buf.size(), ssz = sig.size();
    for (size_t i = 0; i + ssz <= bsz; ++i) {
        bool match = true;
        for (size_t j = 0; j < ssz; ++j)
            if (!sig[j].wildcard && buf[i + j] != sig[j].value) { match = false; break; }
        if (match && ++count > maxPrint) return count;
    }
    return count;
}

std::vector<size_t> FindOccurrences(const std::vector<uint8_t>& buf, const std::vector<SigByte>& sig, size_t maxPrint) {
    std::vector<size_t> occ;
    size_t bsz = buf.size(), ssz = sig.size();
    for (size_t i = 0; i + ssz <= bsz; ++i) {
        bool match = true;
        for (size_t j = 0; j < ssz; ++j)
            if (!sig[j].wildcard && buf[i + j] != sig[j].value) { match = false; break; }
        if (match) { occ.push_back(i); if (occ.size() >= maxPrint) break; }
    }
    return occ;
}

std::string BuildIDA(const std::vector<SigByte>& sig, bool dblqm) {
    std::ostringstream oss;
    for (auto& b : sig) {
        if (b.wildcard) oss << (dblqm ? "??" : "?");
        else oss << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(b.value);
        oss << ' ';
    }
    std::string s = oss.str();
    if (!s.empty()) s.pop_back();
    return s;
}

std::string BuildCByteArrayMask(const std::vector<SigByte>& sig) {
    std::ostringstream pat, mask;
    for (auto& b : sig) {
        pat << "\\x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << (b.wildcard ? 0 : b.value);
        mask << (b.wildcard ? '?' : 'x');
    }
    return pat.str() + " " + mask.str();
}

std::string BuildCRawBytesBitmask(const std::vector<SigByte>& sig) {
    std::ostringstream pat;
    std::string bm;
    for (auto& b : sig) {
        pat << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << (b.wildcard ? 0 : b.value) << ", ";
        bm.push_back(b.wildcard ? '0' : '1');
    }
    std::string pstr = pat.str();
    if (pstr.size() >= 2) pstr.resize(pstr.size() - 2);
    std::reverse(bm.begin(), bm.end());
    return pstr + " 0b" + bm;
}

std::string FormatSignature(const std::vector<SigByte>& sig, SigFormat fmt) {
    switch (fmt) {
    case SigFormat::IDA:            return BuildIDA(sig, false);
    case SigFormat::X64dbg:         return BuildIDA(sig, true);
    case SigFormat::CByteArrayMask: return BuildCByteArrayMask(sig);
    case SigFormat::CRawBytesBitmask: return BuildCRawBytesBitmask(sig);
    default: return {};
    }
}

std::string GetModuleName(HANDLE hP, HMODULE m) {
    char name[MAX_PATH] = {};
    if (GetModuleFileNameExA(hP, m, name, MAX_PATH)) {
        std::string p(name);
        auto pos = p.find_last_of("\\/");
        return (pos == std::string::npos ? p : p.substr(pos + 1));
    }
    return "<unknown>";
}

int main() {
    size_t maxSigLen = DEFAULT_MAX_SIG_LEN;
    size_t maxPrint = DEFAULT_MAX_PRINT_OCC;
    SigFormat sigFmt = SigFormat::IDA;

    while (true) {
        system("cls");
        std::cout << "==== SigMakerEXT ====\n"
            << "1. Generate Signature\n"
            << "2. Scan Signature\n"
            << "3. Settings\n"
            << "Any other to Exit\n"
            << "Select option: ";
        std::string sel; std::getline(std::cin, sel);
        int op = 0; try { op = std::stoi(sel); }
        catch (...) { break; }

        if (op == 3) {
            system("cls");
            std::cout << "-- Settings --\n"
                << "Select signature format with example:\n"
                << "1. IDA             (E8 ? ? ? ? 45 33 F6 66 44 89 34 33)\n"
                << "2. x64Dbg          (E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33)\n"
                << "3. C Byte Array+Mask   (\\xE8\\x00... x????xxxxxxxx)\n"
                << "4. C Raw Bytes+Bitmask (0xE8,0x00... 0b1111111100001)\n"
                << "Choice: ";
            std::getline(std::cin, sel);
            int f = 0; try { f = std::stoi(sel); }
            catch (...) {}
            if (f >= 1 && f <= 4) sigFmt = static_cast<SigFormat>(f);

            std::cout << "Max signature length (" << maxSigLen << "): ";
            std::getline(std::cin, sel); size_t ml = std::stoul(sel); if (ml > 0) maxSigLen = ml;
            std::cout << "Max occurrences display (" << maxPrint << "): ";
            std::getline(std::cin, sel); size_t mp = std::stoul(sel); if (mp > 0) maxPrint = mp;
            std::cout << "Settings updated.\n";
            system("pause");
            continue;
        }

        system("cls");
        std::cout << "-- Process Input --\n"
            << "Enter PID (hex 0x... or decimal): ";
        std::string pidStr; std::getline(std::cin, pidStr);
        DWORD pid = (pidStr.rfind("0x", 0) == 0 || pidStr.rfind("0X", 0) == 0)
            ? std::stoul(pidStr, nullptr, 16)
            : std::stoul(pidStr, nullptr, 10);
        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) {
            std::cerr << "Failed to open PID=" << pid << "\n";
            system("pause");
            continue;
        }

        if (op == 1) {
            system("cls");
            std::cout << "-- Generate Signature --\n"
                << "Enter address (hex, with or without 0x): ";
            std::string addr; std::getline(std::cin, addr);
            if (addr.rfind("0x", 0) == 0 || addr.rfind("0X", 0) == 0) addr = addr.substr(2);
            uintptr_t tgt = std::stoull(addr, nullptr, 16);

            void* basePtr; size_t modSz;
            auto buf = ReadModuleBytes(hProc, (void*)tgt, &basePtr, &modSz);
            uintptr_t base = reinterpret_cast<uintptr_t>(basePtr);
            std::vector<SigByte> sig;
            uintptr_t cur = tgt;

            while (true) {
                size_t off = cur - base;
                hde64s d; size_t len = hde64_disasm(buf.data() + off, &d);
                if (len == 0) throw std::runtime_error("Disassembly failed");
                uint32_t f = d.flags;
                size_t imm = (f & F_IMM8) ? 1
                    : (f & F_IMM16) ? 2
                    : (f & F_IMM32) ? 4
                    : (f & F_IMM64) ? 8 : 0;
                size_t disp = (f & F_DISP8) ? 1
                    : (f & F_DISP16) ? 2
                    : (f & F_DISP32) ? 4 : 0;
                size_t opSz = imm + disp;
                size_t opOff = opSz > 0 ? len - opSz : len;
                for (size_t i = 0; i < len; ++i)
                    sig.push_back({ buf[off + i], static_cast<bool>(i >= opOff && i < opOff + opSz) });
                if (sig.size() > maxSigLen) throw std::runtime_error("Signature too long");
                auto sstr = FormatSignature(sig, sigFmt);
                size_t tot = CountOccurrences(buf, sig, maxPrint);
                auto occ = FindOccurrences(buf, sig, maxPrint);

                std::cout << "\nSignature: " << sstr << "\n";
                std::cout << (tot > maxPrint ? "Occurrences: >" : "Occurrences: ")
                    << std::min(tot, maxPrint) << "\n";
                for (size_t i = 0; i < occ.size(); ++i)
                    std::cout << " " << std::setw(2) << i + 1
                    << ". 0x" << std::hex << (base + occ[i]) << std::dec << "\n";
                if (tot == 1) {
                    std::cout << "\nUnique signature: " << sstr << "\n";
                    break;
                }
                cur += len;
            }
        }
        else if (op == 2) {
            system("cls");
            std::cout << "-- Scan Signature --\n"
                << "Enter signature string:\n";
            std::string in; std::getline(std::cin, in);
            auto sig = ParseSignature(in);
            auto sstr = FormatSignature(sig, sigFmt);
            std::cout << "Parsed: " << sstr << "\n\n";

            HMODULE mods[1024]; DWORD cb;
            EnumProcessModules(hProc, mods, sizeof(mods), &cb);
            size_t mc = cb / sizeof(HMODULE);
            for (size_t i = 0; i < mc; ++i) {
                MODULEINFO mi;
                if (!GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) continue;
                auto mb = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
                size_t msz = mi.SizeOfImage;
                std::vector<uint8_t> buf(msz); SIZE_T rd;
                if (!ReadProcessMemory(hProc, mb, buf.data(), msz, &rd)) continue;
                size_t tot = CountOccurrences(buf, sig, maxPrint);
                if (!tot) continue;
                auto occ = FindOccurrences(buf, sig, maxPrint);
                std::string name = GetModuleName(hProc, mods[i]);
                std::cout << "Module: " << name << "\n";
                std::cout << (tot > maxPrint ? "Occurrences: >" : "Occurrences: ")
                    << std::min(tot, maxPrint) << "\n";
                for (size_t j = 0; j < occ.size(); ++j)
                    std::cout << " " << std::setw(2) << j + 1
                    << ". 0x" << std::hex << (reinterpret_cast<uintptr_t>(mb) + occ[j]) << std::dec << "\n";
                std::cout << "\n";
            }
        }

        system("pause");
    }

    return 0;
}
