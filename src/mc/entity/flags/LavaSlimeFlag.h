#pragma once

#include "mc/_HeaderOutputPredefine.h"

struct LavaSlimeFlag {

public:
    // prevent constructor by default
    LavaSlimeFlag& operator=(LavaSlimeFlag const&) = delete;
    LavaSlimeFlag(LavaSlimeFlag const&)            = delete;
    LavaSlimeFlag()                                = delete;
};
