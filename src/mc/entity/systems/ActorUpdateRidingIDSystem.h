#pragma once

#include "mc/_HeaderOutputPredefine.h"

class ActorUpdateRidingIDSystem {

public:
    // prevent constructor by default
    ActorUpdateRidingIDSystem& operator=(ActorUpdateRidingIDSystem const&) = delete;
    ActorUpdateRidingIDSystem(ActorUpdateRidingIDSystem const&)            = delete;
    ActorUpdateRidingIDSystem()                                            = delete;

public:
    /**
     * @symbol ?createClearPrevRidingIDSystem\@ActorUpdateRidingIDSystem\@\@SA?AUTickingSystemWithInfo\@\@XZ
     */
    MCAPI static struct TickingSystemWithInfo createClearPrevRidingIDSystem(); // NOLINT
    /**
     * @symbol ?createClearRidingIDSystem\@ActorUpdateRidingIDSystem\@\@SA?AUTickingSystemWithInfo\@\@XZ
     */
    MCAPI static struct TickingSystemWithInfo createClearRidingIDSystem(); // NOLINT
    /**
     * @symbol ?createUpdatePrevRidingIDSystem\@ActorUpdateRidingIDSystem\@\@SA?AUTickingSystemWithInfo\@\@XZ
     */
    MCAPI static struct TickingSystemWithInfo createUpdatePrevRidingIDSystem(); // NOLINT
};
