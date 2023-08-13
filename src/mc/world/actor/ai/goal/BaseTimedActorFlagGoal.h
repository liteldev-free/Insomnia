#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/AutomaticID.h"
#include "mc/world/actor/ai/goal/Goal.h"

class BaseTimedActorFlagGoal : public ::Goal {

public:
    // prevent constructor by default
    BaseTimedActorFlagGoal& operator=(BaseTimedActorFlagGoal const&) = delete;
    BaseTimedActorFlagGoal(BaseTimedActorFlagGoal const&)            = delete;
    BaseTimedActorFlagGoal()                                         = delete;

public:
    // NOLINTBEGIN
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0();
    /**
     * @vftbl 1
     * @symbol ?canUse\@BaseTimedActorFlagGoal\@\@UEAA_NXZ
     */
    virtual bool canUse();
    /**
     * @vftbl 2
     * @symbol ?canContinueToUse\@BaseTimedActorFlagGoal\@\@UEAA_NXZ
     */
    virtual bool canContinueToUse();
    /**
     * @vftbl 4
     * @symbol ?start\@BaseTimedActorFlagGoal\@\@UEAAXXZ
     */
    virtual void start();
    /**
     * @vftbl 5
     * @symbol ?stop\@BaseTimedActorFlagGoal\@\@UEAAXXZ
     */
    virtual void stop();
    /**
     * @vftbl 6
     * @symbol ?tick\@BaseTimedActorFlagGoal\@\@UEAAXXZ
     */
    virtual void tick();
    /**
     * @vftbl 7
     * @symbol
     * ?appendDebugInfo\@BaseTimedActorFlagGoal\@\@UEBAXAEAV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    virtual void appendDebugInfo(std::string&) const;
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_BASETIMEDACTORFLAGGOAL
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~BaseTimedActorFlagGoal();
#endif
    /**
     * @symbol ??0BaseTimedActorFlagGoal\@\@QEAA\@AEAVMob\@\@W4ActorFlags\@\@\@Z
     */
    MCAPI BaseTimedActorFlagGoal(class Mob&, enum class ActorFlags);
    // NOLINTEND
};
