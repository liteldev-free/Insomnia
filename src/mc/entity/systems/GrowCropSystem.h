#pragma once

#include "mc/_HeaderOutputPredefine.h"

class GrowCropSystem {

public:
    // prevent constructor by default
    GrowCropSystem& operator=(GrowCropSystem const&) = delete;
    GrowCropSystem(GrowCropSystem const&)            = delete;
    GrowCropSystem()                                 = delete;

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
     * @symbol ?tick\@GrowCropSystem\@\@UEAAXAEAVEntityRegistry\@\@\@Z
     */
    virtual void tick(class EntityRegistry&); // NOLINT
};
