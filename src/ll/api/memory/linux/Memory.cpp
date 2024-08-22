#include "ll/api/memory/Memory.h"

#include "pl/SymbolProvider.h"

#include <sys/mman.h>
#include <unistd.h>

namespace ll::memory {

FuncPtr resolveSignature(std::string_view signature, std::span<std::byte> range) {
    // TODO.
    return nullptr;
}

void modify(void* ptr, size_t len, const std::function<void()>& callback) {
    // VirtualProtect(ptr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    callback();
    // VirtualProtect(ptr, len, oldProtect, &oldProtect);
}

static int getPosixProtectionFlag(unsigned flags) {
    switch (flags & MF_RWE_MASK) {
    case MF_READ:
        return PROT_READ;
    case MF_WRITE:
        return PROT_WRITE;
    case MF_READ | MF_WRITE:
        return PROT_READ | PROT_WRITE;
    case MF_READ | MF_EXEC:
        return PROT_READ | PROT_EXEC;
    case MF_READ | MF_WRITE | MF_EXEC:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    case MF_EXEC:
#if defined(__FreeBSD__) || defined(__powerpc__)
        // On PowerPC, having an executable page that has no read permission
        // can have unintended consequences.  The function InvalidateInstruction-
        // Cache uses instructions dcbf and icbi, both of which are treated by
        // the processor as loads.  If the page has no read permissions,
        // executing these instructions will result in a segmentation fault.
        return PROT_READ | PROT_EXEC;
#else
        return PROT_EXEC;
#endif
    default:
        // Illegal memory protection flag specified!
        LL_UNREACHABLE;
    }
    // Provide a default return value as required by some compilers.
    return PROT_NONE;
}

void* vallocate(size_t size, ProtectionFlag flag) {
    if (size == 0) return nullptr;

    // On platforms that have it, we can use MAP_ANON to get a memory-mapped
    // page without file backing, but we need a fallback of opening /dev/zero
    // for strictly POSIX platforms instead.
    int fd;
#if defined(MAP_ANON)
    fd = -1;
#else
    fd = open("/dev/zero", O_RDWR);
    if (fd == -1) return nullptr;
#endif

    int mmFlags = MAP_PRIVATE;
#if defined(MAP_ANON)
    mmFlags |= MAP_ANON;
#endif
    int protectFlags = getPosixProtectionFlag(flag);

#if defined(__NetBSD__) && defined(PROT_MPROTECT)
    Protect |= PROT_MPROTECT(PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    // FIXME: Handle huge page requests (MF_HUGE_HINT).
    void* result = ::mmap(nullptr, size, protectFlags, mmFlags, fd, 0);
    if (result == MAP_FAILED) {
#if !defined(MAP_ANON)
        close(fd);
#endif
        return nullptr;
    }

#if !defined(MAP_ANON)
    close(fd);
#endif

    return result;
}

unsigned vquery(void* address) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    char    buffer[4096];
    ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (len <= 0) {
        return 0;
    }
    buffer[len] = '\0';

    auto uintptr = reinterpret_cast<uintptr_t>(address);

    char* line = strtok(buffer, "\n");
    while (line != nullptr) {
        char* start_str = line;
        char* end_str   = strchr(line, '-');
        char* perm_str  = strchr(line, ' ') + 1;

        if (end_str == nullptr || perm_str == nullptr) {
            line = strtok(nullptr, "\n");
            continue;
        }

        *end_str        = '\0';
        uintptr_t start = strtoul(start_str, nullptr, 16);
        uintptr_t end   = strtoul(end_str + 1, nullptr, 16);

        if (uintptr >= start && uintptr < end) {
            int prot = 0;
            if (perm_str[0] == 'r') prot |= PROT_READ;
            if (perm_str[1] == 'w') prot |= PROT_WRITE;
            if (perm_str[2] == 'x') prot |= PROT_EXEC;

            return prot;
        }

        line = strtok(nullptr, "\n");
    }

    return 0;
}

bool vprotect(void* address, size_t size, ProtectionFlag flag) {
    if (address == nullptr || size == 0 || !flag) return false;

    int protectFlag = getPosixProtectionFlag(flag);

    return ::mprotect(address, size, protectFlag) != 0;
}

bool vfree(void* address, size_t size) {
    if (address == nullptr || size == 0) return false;

    return ::munmap(address, size) == 0;
}

} // namespace ll::memory
