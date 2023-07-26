#pragma once

#include "mc/_HeaderOutputPredefine.h"

class EnderChestBlockActor {

public:
    // prevent constructor by default
    EnderChestBlockActor& operator=(EnderChestBlockActor const&) = delete;
    EnderChestBlockActor(EnderChestBlockActor const&)            = delete;
    EnderChestBlockActor()                                       = delete;

public:
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_ENDERCHESTBLOCKACTOR
    /**
     * @symbol ?canPullOutItem\@EnderChestBlockActor\@\@UEBA_NHHAEBVItemStack\@\@\@Z
     */
    MCVAPI bool canPullOutItem(int, int, class ItemStack const&) const; // NOLINT
    /**
     * @symbol ?canPushInItem\@EnderChestBlockActor\@\@UEBA_NHHAEBVItemStack\@\@\@Z
     */
    MCVAPI bool canPushInItem(int, int, class ItemStack const&) const; // NOLINT
    /**
     * @symbol
     * ?getName\@EnderChestBlockActor\@\@UEBA?AV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@XZ
     */
    MCVAPI std::string getName() const; // NOLINT
    /**
     * @symbol ?playCloseSound\@EnderChestBlockActor\@\@MEAAXAEAVBlockSource\@\@\@Z
     */
    MCVAPI void playCloseSound(class BlockSource&); // NOLINT
    /**
     * @symbol ?playOpenSound\@EnderChestBlockActor\@\@MEAAXAEAVBlockSource\@\@\@Z
     */
    MCVAPI void playOpenSound(class BlockSource&); // NOLINT
#endif
    /**
     * @symbol
     * ??0EnderChestBlockActor\@\@QEAA\@W4BlockActorType\@\@AEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@W4BlockActorRendererId\@\@AEBVBlockPos\@\@\@Z
     */
    MCAPI
    EnderChestBlockActor(enum class BlockActorType, std::string const&, enum class BlockActorRendererId, class BlockPos const&); // NOLINT

    // private:

private:
    /**
     * @symbol ?ITEMS_SIZE\@EnderChestBlockActor\@\@0HB
     */
    MCAPI static int const ITEMS_SIZE; // NOLINT
};
