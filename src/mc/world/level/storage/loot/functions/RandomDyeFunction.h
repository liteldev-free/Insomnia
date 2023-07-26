#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/storage/loot/functions/LootItemFunction.h"

// auto generated forward declare list
// clang-format off
namespace mce { class Color; }
// clang-format on

class RandomDyeFunction : public ::LootItemFunction {

public:
    // prevent constructor by default
    RandomDyeFunction& operator=(RandomDyeFunction const&) = delete;
    RandomDyeFunction(RandomDyeFunction const&)            = delete;
    RandomDyeFunction()                                    = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?apply\@RandomDyeFunction\@\@UEAAXAEAVItemStack\@\@AEAVRandom\@\@AEAVLootTableContext\@\@\@Z
     */
    virtual void apply(class ItemStack&, class Random&, class LootTableContext&); // NOLINT
    /**
     * @vftbl 3
     * @symbol ?apply\@RandomDyeFunction\@\@UEAAXAEAVItemInstance\@\@AEAVRandom\@\@AEAVLootTableContext\@\@\@Z
     */
    virtual void apply(class ItemInstance&, class Random&, class LootTableContext&); // NOLINT

    // private:
    /**
     * @symbol ?_applyBase\@RandomDyeFunction\@\@AEBAXAEAVItemStackBase\@\@AEAVRandom\@\@\@Z
     */
    MCAPI void _applyBase(class ItemStackBase&, class Random&) const; // NOLINT
    /**
     * @symbol ?_getRandomArmorColor\@RandomDyeFunction\@\@AEBA?AVColor\@mce\@\@AEAVRandom\@\@\@Z
     */
    MCAPI class mce::Color _getRandomArmorColor(class Random&) const; // NOLINT
    /**
     * @symbol ?_getRandomDyeColor\@RandomDyeFunction\@\@AEBA?AVColor\@mce\@\@AEAVRandom\@\@\@Z
     */
    MCAPI class mce::Color _getRandomDyeColor(class Random&) const; // NOLINT

private:
};
