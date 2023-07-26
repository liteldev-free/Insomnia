#pragma once

#include "mc/_HeaderOutputPredefine.h"

class ExplodeSystem {

public:
    // prevent constructor by default
    ExplodeSystem& operator=(ExplodeSystem const&) = delete;
    ExplodeSystem(ExplodeSystem const&)            = delete;
    ExplodeSystem()                                = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol __unk_vfn_1
     */
    virtual void __unk_vfn_1(); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?tick\@ExplodeSystem\@\@UEAAXAEAVEntityRegistry\@\@\@Z
     */
    virtual void tick(class EntityRegistry&); // NOLINT
};
