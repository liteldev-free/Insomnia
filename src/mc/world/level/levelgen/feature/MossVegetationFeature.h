#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/levelgen/feature/Feature.h"

class MossVegetationFeature : public ::Feature {

public:
    // prevent constructor by default
    MossVegetationFeature& operator=(MossVegetationFeature const&) = delete;
    MossVegetationFeature(MossVegetationFeature const&)            = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 3
     * @symbol ?place\@MossVegetationFeature\@\@UEBA_NAEAVBlockSource\@\@AEBVBlockPos\@\@AEAVRandom\@\@\@Z
     */
    virtual bool place(class BlockSource&, class BlockPos const&, class Random&) const; // NOLINT
    /**
     * @symbol ??0MossVegetationFeature\@\@QEAA\@XZ
     */
    MCAPI MossVegetationFeature(); // NOLINT
};
