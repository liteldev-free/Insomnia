#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/core/common/bedrock/Result.h"
#include "mc/deps/core/data/BidirectionalUnorderedMap.h"

class ItemStackRequestAction {

public:
    // prevent constructor by default
    ItemStackRequestAction& operator=(ItemStackRequestAction const&) = delete;
    ItemStackRequestAction(ItemStackRequestAction const&)            = delete;
    ItemStackRequestAction()                                         = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?getCraftAction\@ItemStackRequestAction\@\@UEBAPEBVItemStackRequestActionCraftBase\@\@XZ
     */
    virtual class ItemStackRequestActionCraftBase const* getCraftAction() const; // NOLINT
    /**
     * @vftbl 2
     * @symbol ?getFilteredStringIndex\@ItemStackRequestAction\@\@UEBAHXZ
     */
    virtual int getFilteredStringIndex() const; // NOLINT
    /**
     * @vftbl 3
     * @symbol ?postLoadItems_DEPRECATEDASKTYLAING\@ItemStackRequestAction\@\@UEAAXAEAVBlockPalette\@\@_N\@Z
     */
    virtual void postLoadItems_DEPRECATEDASKTYLAING(class BlockPalette&, bool); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_ITEMSTACKREQUESTACTION
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~ItemStackRequestAction(); // NOLINT
#endif
    /**
     * @symbol ??0ItemStackRequestAction\@\@QEAA\@W4ItemStackRequestActionType\@\@\@Z
     */
    MCAPI ItemStackRequestAction(enum class ItemStackRequestActionType); // NOLINT
    /**
     * @symbol ?getActionType\@ItemStackRequestAction\@\@QEBA?AW4ItemStackRequestActionType\@\@XZ
     */
    MCAPI enum class ItemStackRequestActionType getActionType() const; // NOLINT
    /**
     * @symbol
     * ?getActionTypeName\@ItemStackRequestAction\@\@SA?BV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@W4ItemStackRequestActionType\@\@\@Z
     */
    MCAPI static std::string const getActionTypeName(enum class ItemStackRequestActionType); // NOLINT
    /**
     * @symbol
     * ?read\@ItemStackRequestAction\@\@SA?AV?$Result\@V?$unique_ptr\@VItemStackRequestAction\@\@U?$default_delete\@VItemStackRequestAction\@\@\@std\@\@\@std\@\@Verror_code\@2\@\@Bedrock\@\@AEAVReadOnlyBinaryStream\@\@\@Z
     */
    MCAPI static class Bedrock::Result<std::unique_ptr<class ItemStackRequestAction>, class std::error_code>
    read(class ReadOnlyBinaryStream&); // NOLINT

    // private:

private:
    /**
     * @symbol
     * ?actionTypeMap\@ItemStackRequestAction\@\@0V?$BidirectionalUnorderedMap\@W4ItemStackRequestActionType\@\@V?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@\@B
     */
    MCAPI static class BidirectionalUnorderedMap<enum class ItemStackRequestActionType, std::string> const
        actionTypeMap; // NOLINT
};
