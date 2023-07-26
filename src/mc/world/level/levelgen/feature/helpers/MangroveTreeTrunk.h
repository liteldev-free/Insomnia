#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated forward declare list
// clang-format off
namespace TreeHelper { struct TreeParams; }
// clang-format on

class MangroveTreeTrunk {

public:
    // prevent constructor by default
    MangroveTreeTrunk& operator=(MangroveTreeTrunk const&) = delete;
    MangroveTreeTrunk(MangroveTreeTrunk const&)            = delete;
    MangroveTreeTrunk()                                    = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol
     * ?placeTrunk\@MangroveTreeTrunk\@\@UEBA?AV?$optional\@VBlockPos\@\@\@std\@\@AEAVIBlockWorldGenAPI\@\@AEBVBlockPos\@\@AEAVRandom\@\@HAEAVRenderParams\@\@AEBUTreeParams\@TreeHelper\@\@PEBVITreeCanopy\@\@\@Z
     */
    virtual class std::optional<class BlockPos>
    placeTrunk(class IBlockWorldGenAPI&, class BlockPos const&, class Random&, int, class RenderParams&, struct TreeHelper::TreeParams const&, class ITreeCanopy const*)
        const; // NOLINT
    /**
     * @vftbl 2
     * @symbol ?getTreeHeight\@MangroveTreeTrunk\@\@UEBAHAEAVRandom\@\@\@Z
     */
    virtual int getTreeHeight(class Random&) const; // NOLINT

    // private:
    /**
     * @symbol
     * ?_placeBranch\@MangroveTreeTrunk\@\@AEBAXAEAVIBlockWorldGenAPI\@\@PEAV?$vector\@VBlockPos\@\@V?$allocator\@VBlockPos\@\@\@std\@\@\@std\@\@AEAVRandom\@\@HAEAVRenderParams\@\@AEBUTreeParams\@TreeHelper\@\@AEAVBlockPos\@\@HEHHPEBVBlock\@\@\@Z
     */
    MCAPI void
    _placeBranch(class IBlockWorldGenAPI&, std::vector<class BlockPos>*, class Random&, int, class RenderParams&, struct TreeHelper::TreeParams const&, class BlockPos&, int, unsigned char, int, int, class Block const*)
        const; // NOLINT

private:
};
