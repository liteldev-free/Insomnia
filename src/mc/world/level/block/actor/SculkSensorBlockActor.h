#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/block/actor/BlockActor.h"

class SculkSensorBlockActor : public ::BlockActor {

public:
    // prevent constructor by default
    SculkSensorBlockActor& operator=(SculkSensorBlockActor const&) = delete;
    SculkSensorBlockActor(SculkSensorBlockActor const&)            = delete;
    SculkSensorBlockActor()                                        = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?load\@SculkSensorBlockActor\@\@UEAAXAEAVLevel\@\@AEBVCompoundTag\@\@AEAVDataLoadHelper\@\@\@Z
     */
    virtual void load(class Level&, class CompoundTag const&, class DataLoadHelper&); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?save\@SculkSensorBlockActor\@\@UEBA_NAEAVCompoundTag\@\@\@Z
     */
    virtual bool save(class CompoundTag&) const; // NOLINT
    /**
     * @vftbl 7
     * @symbol ?tick\@SculkSensorBlockActor\@\@UEAAXAEAVBlockSource\@\@\@Z
     */
    virtual void tick(class BlockSource&); // NOLINT
    /**
     * @vftbl 12
     * @symbol __unk_vfn_12
     */
    virtual void __unk_vfn_12(); // NOLINT
    /**
     * @vftbl 13
     * @symbol ?onRemoved\@SculkSensorBlockActor\@\@UEAAXAEAVBlockSource\@\@\@Z
     */
    virtual void onRemoved(class BlockSource&); // NOLINT
    /**
     * @vftbl 18
     * @symbol __unk_vfn_18
     */
    virtual void __unk_vfn_18(); // NOLINT
    /**
     * @vftbl 30
     * @symbol __unk_vfn_30
     */
    virtual void __unk_vfn_30(); // NOLINT
    /**
     * @vftbl 31
     * @symbol __unk_vfn_31
     */
    virtual void __unk_vfn_31(); // NOLINT
    /**
     * @vftbl 32
     * @symbol __unk_vfn_32
     */
    virtual void __unk_vfn_32(); // NOLINT
    /**
     * @vftbl 33
     * @symbol __unk_vfn_33
     */
    virtual void __unk_vfn_33(); // NOLINT
    /**
     * @vftbl 34
     * @symbol __unk_vfn_34
     */
    virtual void __unk_vfn_34(); // NOLINT
    /**
     * @vftbl 35
     * @symbol __unk_vfn_35
     */
    virtual void __unk_vfn_35(); // NOLINT
    /**
     * @vftbl 36
     * @symbol __unk_vfn_36
     */
    virtual void __unk_vfn_36(); // NOLINT
    /**
     * @vftbl 39
     * @symbol __unk_vfn_39
     */
    virtual void __unk_vfn_39(); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_SCULKSENSORBLOCKACTOR
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~SculkSensorBlockActor(); // NOLINT
#endif
    /**
     * @symbol
     * ??0SculkSensorBlockActor\@\@QEAA\@W4BlockActorType\@\@AEBVBlockPos\@\@AEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@I$$QEAV?$unique_ptr\@VSculkSensorVibrationConfig\@\@U?$default_delete\@VSculkSensorVibrationConfig\@\@\@std\@\@\@4\@\@Z
     */
    MCAPI
    SculkSensorBlockActor(enum class BlockActorType, class BlockPos const&, std::string const&, unsigned int, std::unique_ptr<class SculkSensorVibrationConfig>&&); // NOLINT
    /**
     * @symbol ??0SculkSensorBlockActor\@\@QEAA\@AEBVBlockPos\@\@\@Z
     */
    MCAPI SculkSensorBlockActor(class BlockPos const&); // NOLINT
    /**
     * @symbol ?getLatestReceivedVibrationFrequency\@SculkSensorBlockActor\@\@QEBAHXZ
     */
    MCAPI int getLatestReceivedVibrationFrequency() const; // NOLINT
};
