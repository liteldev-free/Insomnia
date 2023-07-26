#pragma once

#include "mc/_HeaderOutputPredefine.h"

class BossSystem {

public:
    // prevent constructor by default
    BossSystem& operator=(BossSystem const&) = delete;
    BossSystem(BossSystem const&)            = delete;
    BossSystem()                             = delete;

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
     * @symbol ?tick\@BossSystem\@\@UEAAXAEAVEntityRegistry\@\@\@Z
     */
    virtual void tick(class EntityRegistry&); // NOLINT
};
