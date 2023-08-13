#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/AutomaticID.h"
#include "mc/world/actor/ai/goal/Goal.h"

class DragonHoldingPatternGoal : public ::Goal {

public:
    // prevent constructor by default
    DragonHoldingPatternGoal& operator=(DragonHoldingPatternGoal const&) = delete;
    DragonHoldingPatternGoal(DragonHoldingPatternGoal const&)            = delete;
    DragonHoldingPatternGoal()                                           = delete;

public:
    // NOLINTBEGIN
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0();
    /**
     * @vftbl 1
     * @symbol ?canUse\@DragonHoldingPatternGoal\@\@UEAA_NXZ
     */
    virtual bool canUse();
    /**
     * @vftbl 2
     * @symbol ?canContinueToUse\@DragonHoldingPatternGoal\@\@UEAA_NXZ
     */
    virtual bool canContinueToUse();
    /**
     * @vftbl 4
     * @symbol ?start\@DragonHoldingPatternGoal\@\@UEAAXXZ
     */
    virtual void start();
    /**
     * @vftbl 5
     * @symbol ?stop\@DragonHoldingPatternGoal\@\@UEAAXXZ
     */
    virtual void stop();
    /**
     * @vftbl 6
     * @symbol ?tick\@DragonHoldingPatternGoal\@\@UEAAXXZ
     */
    virtual void tick();
    /**
     * @vftbl 7
     * @symbol
     * ?appendDebugInfo\@DragonHoldingPatternGoal\@\@UEBAXAEAV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    virtual void appendDebugInfo(std::string&) const;
    /**
     * @symbol ??0DragonHoldingPatternGoal\@\@QEAA\@AEAVEnderDragon\@\@\@Z
     */
    MCAPI DragonHoldingPatternGoal(class EnderDragon&);
    // NOLINTEND

    // private:
    // NOLINTBEGIN
    /**
     * @symbol ?findNewTarget\@DragonHoldingPatternGoal\@\@AEAAXXZ
     */
    MCAPI void findNewTarget();
    // NOLINTEND
};
