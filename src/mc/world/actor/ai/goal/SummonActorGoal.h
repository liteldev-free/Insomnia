#pragma once

#include "mc/_HeaderOutputPredefine.h"

class SummonActorGoal {

public:
    // prevent constructor by default
    SummonActorGoal& operator=(SummonActorGoal const&) = delete;
    SummonActorGoal(SummonActorGoal const&)            = delete;
    SummonActorGoal()                                  = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?canUse\@SummonActorGoal\@\@UEAA_NXZ
     */
    virtual bool canUse(); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?canContinueToUse\@SummonActorGoal\@\@UEAA_NXZ
     */
    virtual bool canContinueToUse(); // NOLINT
    /**
     * @vftbl 3
     * @symbol __unk_vfn_3
     */
    virtual void __unk_vfn_3(); // NOLINT
    /**
     * @vftbl 4
     * @symbol ?start\@SummonActorGoal\@\@UEAAXXZ
     */
    virtual void start(); // NOLINT
    /**
     * @vftbl 5
     * @symbol ?stop\@SummonActorGoal\@\@UEAAXXZ
     */
    virtual void stop(); // NOLINT
    /**
     * @vftbl 6
     * @symbol ?tick\@SummonActorGoal\@\@UEAAXXZ
     */
    virtual void tick(); // NOLINT
    /**
     * @vftbl 7
     * @symbol
     * ?appendDebugInfo\@SummonActorGoal\@\@UEBAXAEAV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    virtual void appendDebugInfo(std::string&) const; // NOLINT
    /**
     * @symbol
     * ??0SummonActorGoal\@\@QEAA\@AEAVMob\@\@AEBV?$vector\@USummonSpellData\@\@V?$allocator\@USummonSpellData\@\@\@std\@\@\@std\@\@\@Z
     */
    MCAPI SummonActorGoal(class Mob&, std::vector<struct SummonSpellData> const&); // NOLINT

    // private:
    /**
     * @symbol ?_createSpellEntity\@SummonActorGoal\@\@AEBAXMMMMMHUActorDefinitionIdentifier\@\@\@Z
     */
    MCAPI void
    _createSpellEntity(float, float, float, float, float, int, struct ActorDefinitionIdentifier) const; // NOLINT
    /**
     * @symbol ?_selectBestSpell\@SummonActorGoal\@\@AEBAHAEAVActor\@\@\@Z
     */
    MCAPI int _selectBestSpell(class Actor&) const; // NOLINT

private:
};
