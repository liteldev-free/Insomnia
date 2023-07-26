#pragma once

#include "mc/_HeaderOutputPredefine.h"

class SynchedActorDataReader {

public:
    // prevent constructor by default
    SynchedActorDataReader& operator=(SynchedActorDataReader const&) = delete;
    SynchedActorDataReader(SynchedActorDataReader const&)            = delete;
    SynchedActorDataReader()                                         = delete;

public:
    /**
     * @symbol ?getInt\@SynchedActorDataReader\@\@QEBAHG\@Z
     */
    MCAPI int getInt(unsigned short) const; // NOLINT
    /**
     * @symbol ?getPosition\@SynchedActorDataReader\@\@QEBA?AVBlockPos\@\@G\@Z
     */
    MCAPI class BlockPos getPosition(unsigned short) const; // NOLINT
    /**
     * @symbol ?getStatusFlag\@SynchedActorDataReader\@\@QEBA_NW4ActorFlags\@\@\@Z
     */
    MCAPI bool getStatusFlag(enum class ActorFlags) const; // NOLINT
    /**
     * @symbol ?getVec3\@SynchedActorDataReader\@\@QEBA?AVVec3\@\@G\@Z
     */
    MCAPI class Vec3 getVec3(unsigned short) const; // NOLINT
};
