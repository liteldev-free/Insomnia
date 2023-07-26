#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/network/TypedServerNetId.h"

class CreativeItemRegistry {

public:
    // prevent constructor by default
    CreativeItemRegistry& operator=(CreativeItemRegistry const&) = delete;
    CreativeItemRegistry(CreativeItemRegistry const&)            = delete;

public:
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_CREATIVEITEMREGISTRY
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~CreativeItemRegistry(); // NOLINT
#endif
    /**
     * @symbol ??0CreativeItemRegistry\@\@QEAA\@XZ
     */
    MCAPI CreativeItemRegistry(); // NOLINT
    /**
     * @symbol ?findCreativeItemEntry\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemEntry\@\@AEBVItemInstance\@\@\@Z
     */
    MCAPI class CreativeItemEntry* findCreativeItemEntry(class ItemInstance const&); // NOLINT
    /**
     * @symbol
     * ?findCreativeItemEntry\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemEntry\@\@AEBV?$TypedServerNetId\@UCreativeItemNetIdTag\@\@I$0A\@\@\@\@Z
     */
    MCAPI class CreativeItemEntry*
    findCreativeItemEntry(class TypedServerNetId<struct CreativeItemNetIdTag, unsigned int, 0> const&); // NOLINT
    /**
     * @symbol
     * ?getCreativeCategory\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemGroupCategory\@\@W4CreativeItemCategory\@\@\@Z
     */
    MCAPI class CreativeItemGroupCategory* getCreativeCategory(enum class CreativeItemCategory); // NOLINT
    /**
     * @symbol
     * ?getCreativeItemEntries\@CreativeItemRegistry\@\@QEAAAEBV?$vector\@VCreativeItemEntry\@\@V?$allocator\@VCreativeItemEntry\@\@\@std\@\@\@std\@\@XZ
     */
    MCAPI std::vector<class CreativeItemEntry> const& getCreativeItemEntries(); // NOLINT
    /**
     * @symbol ?getItemEntry\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemEntry\@\@I\@Z
     */
    MCAPI class CreativeItemEntry* getItemEntry(unsigned int); // NOLINT
    /**
     * @symbol
     * ?newCreativeCategory\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemGroupCategory\@\@AEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@W4CreativeItemCategory\@\@\@Z
     */
    MCAPI class CreativeItemGroupCategory*
    newCreativeCategory(std::string const&, enum class CreativeItemCategory); // NOLINT
    /**
     * @symbol
     * ?newCreativeGroup\@CreativeItemRegistry\@\@QEAAPEAVCreativeGroupInfo\@\@W4CreativeItemCategory\@\@AEBVHashedString\@\@AEBVItemInstance\@\@\@Z
     */
    MCAPI class CreativeGroupInfo*
    newCreativeGroup(enum class CreativeItemCategory, class HashedString const&, class ItemInstance const&); // NOLINT
    /**
     * @symbol
     * ?newItemEntry\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemEntry\@\@AEBV?$TypedServerNetId\@UCreativeItemNetIdTag\@\@I$0A\@\@\@AEBVItemInstance\@\@\@Z
     */
    MCAPI class CreativeItemEntry*
    newItemEntry(class TypedServerNetId<struct CreativeItemNetIdTag, unsigned int, 0> const&, class ItemInstance const&); // NOLINT
    /**
     * @symbol ?resetGroups\@CreativeItemRegistry\@\@QEAAXXZ
     */
    MCAPI void resetGroups(); // NOLINT
    /**
     * @symbol ?updateItemEntry\@CreativeItemRegistry\@\@QEAAPEAVCreativeItemEntry\@\@IAEBVItemInstance\@\@\@Z
     */
    MCAPI class CreativeItemEntry* updateItemEntry(unsigned int, class ItemInstance const&); // NOLINT
    /**
     * @symbol ?updateNetIdMap\@CreativeItemRegistry\@\@QEAAXXZ
     */
    MCAPI void updateNetIdMap(); // NOLINT
    /**
     * @symbol ?current\@CreativeItemRegistry\@\@SAPEAV1\@XZ
     */
    MCAPI static class CreativeItemRegistry* current(); // NOLINT
    /**
     * @symbol
     * ?forEachCreativeItemInstance\@CreativeItemRegistry\@\@SAXV?$function\@$$A6A_NAEAVItemInstance\@\@\@Z\@std\@\@\@Z
     */
    MCAPI static void forEachCreativeItemInstance(class std::function<bool(class ItemInstance&)>); // NOLINT
    /**
     * @symbol
     * ?setCurrentRegistry\@CreativeItemRegistry\@\@SAX$$QEAV?$unique_ptr\@VCreativeItemRegistry\@\@U?$default_delete\@VCreativeItemRegistry\@\@\@std\@\@\@std\@\@\@Z
     */
    MCAPI static void setCurrentRegistry(std::unique_ptr<class CreativeItemRegistry>&&); // NOLINT
    /**
     * @symbol ?mCreativeListMutex\@CreativeItemRegistry\@\@2Vmutex\@std\@\@A
     */
    MCAPI static class std::mutex mCreativeListMutex; // NOLINT

    // private:
    /**
     * @symbol
     * ?_forEachCreativeItemInstance\@CreativeItemRegistry\@\@AEAAXV?$function\@$$A6A_NAEAVItemInstance\@\@\@Z\@std\@\@\@Z
     */
    MCAPI void _forEachCreativeItemInstance(class std::function<bool(class ItemInstance&)>); // NOLINT

private:
    /**
     * @symbol
     * ?mCurrentRegistry\@CreativeItemRegistry\@\@0V?$unique_ptr\@VCreativeItemRegistry\@\@U?$default_delete\@VCreativeItemRegistry\@\@\@std\@\@\@std\@\@A
     */
    MCAPI static std::unique_ptr<class CreativeItemRegistry> mCurrentRegistry; // NOLINT
};
