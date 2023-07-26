#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/actor/ai/goal/target/NearestAttackableTargetGoal.h"

class DefendTrustedTargetGoal : public ::NearestAttackableTargetGoal {

public:
    // prevent constructor by default
    DefendTrustedTargetGoal& operator=(DefendTrustedTargetGoal const&) = delete;
    DefendTrustedTargetGoal(DefendTrustedTargetGoal const&)            = delete;
    DefendTrustedTargetGoal()                                          = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?canUse\@DefendTrustedTargetGoal\@\@UEAA_NXZ
     */
    virtual bool canUse(); // NOLINT
    /**
     * @vftbl 4
     * @symbol ?start\@DefendTrustedTargetGoal\@\@UEAAXXZ
     */
    virtual void start(); // NOLINT
    /**
     * @vftbl 7
     * @symbol
     * ?appendDebugInfo\@DefendTrustedTargetGoal\@\@UEBAXAEAV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    virtual void appendDebugInfo(std::string&) const; // NOLINT
    /**
     * @vftbl 8
     * @symbol __unk_vfn_8
     */
    virtual void __unk_vfn_8(); // NOLINT
    /**
     * @vftbl 9
     * @symbol __unk_vfn_9
     */
    virtual void __unk_vfn_9(); // NOLINT
    /**
     * @symbol
     * ??0DefendTrustedTargetGoal\@\@QEAA\@AEAVMob\@\@AEBV?$vector\@UMobDescriptor\@\@V?$allocator\@UMobDescriptor\@\@\@std\@\@\@std\@\@MH_NHW4LevelSoundEvent\@\@AEBVActorDefinitionTrigger\@\@\@Z
     */
    MCAPI
    DefendTrustedTargetGoal(class Mob&, std::vector<struct MobDescriptor> const&, float, int, bool, int, enum class LevelSoundEvent, class ActorDefinitionTrigger const&); // NOLINT

    // private:
    /**
     * @symbol ?_findTrustedTarget\@DefendTrustedTargetGoal\@\@AEAA?AUActorUniqueID\@\@AEBVTrustComponent\@\@\@Z
     */
    MCAPI struct ActorUniqueID _findTrustedTarget(class TrustComponent const&); // NOLINT

private:
};
