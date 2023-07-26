#pragma once

#include "mc/_HeaderOutputPredefine.h"

class Vec4 {

public:
    // prevent constructor by default
    Vec4& operator=(Vec4 const&) = delete;
    Vec4(Vec4 const&)            = delete;
    Vec4()                       = delete;

public:
    /**
     * @symbol ?MAX\@Vec4\@\@2V1\@B
     */
    MCAPI static class Vec4 const MAX; // NOLINT
    /**
     * @symbol ?MIN\@Vec4\@\@2V1\@B
     */
    MCAPI static class Vec4 const MIN; // NOLINT
    /**
     * @symbol ?ONE\@Vec4\@\@2V1\@B
     */
    MCAPI static class Vec4 const ONE; // NOLINT
    /**
     * @symbol ?ZERO\@Vec4\@\@2V1\@B
     */
    MCAPI static class Vec4 const ZERO; // NOLINT
};
