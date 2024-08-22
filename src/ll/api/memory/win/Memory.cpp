#include "ll/api/memory/Memory.h"

#include <optional>
#include <vector>

#include "ll/api/Logger.h"
#include "ll/api/service/GamingStatus.h"
#include "ll/api/thread/GlobalThreadPauser.h"
#include "ll/api/utils/StringUtils.h"
#include "ll/api/utils/SystemUtils.h"
#include "ll/core/LeviLamina.h"

#include "libhat.hpp"

#include "pl/SymbolProvider.h"

#include "Windows.h"

namespace ll::memory {

// TODO
FuncPtr resolveSignature(std::string_view signature, std::span<std::byte> range) {
    if (range.empty()) {
        return nullptr;
    }
    if (auto res = hat::parse_signature(signature); !res.has_value()) {
        return nullptr;
    } else {
        return const_cast<std::byte*>(hat::find_pattern(range.begin(), range.end(), res.value()).get());
    }
}

void modify(void* ptr, size_t len, const std::function<void()>& callback) {
    std::unique_ptr<thread::GlobalThreadPauser> pauser;
    if (getGamingStatus() != GamingStatus::Default) {
        pauser = std::make_unique<thread::GlobalThreadPauser>();
    }
    DWORD oldProtect;
    VirtualProtect(ptr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    callback();
    VirtualProtect(ptr, len, oldProtect, &oldProtect);
}

static DWORD getWindowsProtectionFlags(unsigned Flags) {
    switch (Flags & MF_RWE_MASK) {
    // Contrary to what you might expect, the Windows page protection flags
    // are not a bitwise combination of RWX values
    case MF_READ:
        return PAGE_READONLY;
    case MF_WRITE:
        // Note: PAGE_WRITE is not supported by VirtualProtect
        return PAGE_READWRITE;
    case MF_READ | MF_WRITE:
        return PAGE_READWRITE;
    case MF_READ | MF_EXEC:
        return PAGE_EXECUTE_READ;
    case MF_READ | MF_WRITE | MF_EXEC:
        return PAGE_EXECUTE_READWRITE;
    case MF_EXEC:
        return PAGE_EXECUTE;
    default:
        // Illegal memory protection flag specified!
        LL_UNREACHABLE;
    }
    // Provide a default return value as required by some compilers.
    return PAGE_NOACCESS;
}

void* vallocate(size_t size, ProtectionFlag flag) {
    if (size == 0) return nullptr;

    DWORD allocFlag   = MEM_RESERVE | MEM_COMMIT;
    DWORD protectFlag = getWindowsProtectionFlags(flag);

    return ::VirtualAlloc(nullptr, size, allocFlag, protectFlag);
}

unsigned vquery(void* address) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(address, &info, sizeof(info)) == 0) {
        return 0; // failed.
    }
    return info.Protect;
}

bool vprotect(void* address, size_t size, ProtectionFlag flag) {
    if (!address || size == 0) return false;

    DWORD protectFlag = getWindowsProtectionFlags(flag);
    DWORD oldFlag;

    return ::VirtualProtect(address, size, protectFlag, &oldFlag);
}

bool vfree(void* address, size_t size) {
    if (!address || size == 0) return false;

    return ::VirtualFree(address, 0, MEM_RELEASE);
}

} // namespace ll::memory
