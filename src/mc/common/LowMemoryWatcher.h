#pragma once

#include "mc/_HeaderOutputPredefine.h"

class LowMemoryWatcher {

public:
    // prevent constructor by default
    LowMemoryWatcher& operator=(LowMemoryWatcher const&) = delete;
    LowMemoryWatcher(LowMemoryWatcher const&)            = delete;
    LowMemoryWatcher()                                   = delete;

    // private:

private:
    /**
     * @symbol ?mPlatformToldUsLowMemory\@LowMemoryWatcher\@\@0_NA
     */
    MCAPI static bool mPlatformToldUsLowMemory; // NOLINT
    /**
     * @symbol
     * ?mPleaseLeakMemory\@LowMemoryWatcher\@\@0V?$list\@V?$vector\@DV?$allocator\@D\@std\@\@\@std\@\@V?$allocator\@V?$vector\@DV?$allocator\@D\@std\@\@\@std\@\@\@2\@\@std\@\@A
     */
    MCAPI static std::list<class std::vector<char, class std::allocator<char>>> mPleaseLeakMemory; // NOLINT
    /**
     * @symbol
     * ?mTimeToResetWarning\@LowMemoryWatcher\@\@0V?$time_point\@Usteady_clock\@chrono\@std\@\@V?$duration\@_JU?$ratio\@$00$0DLJKMKAA\@\@std\@\@\@23\@\@chrono\@std\@\@A
     */
    MCAPI static class std::chrono::time_point<
        struct std::chrono::steady_clock,
        class std::chrono::duration<__int64, struct std::ratio<1, 1000000000>>>
        mTimeToResetWarning; // NOLINT
};
