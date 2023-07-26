#pragma once

#include "mc/_HeaderOutputPredefine.h"

class AmbientSoundServerComponent {

public:
    // prevent constructor by default
    AmbientSoundServerComponent& operator=(AmbientSoundServerComponent const&) = delete;
    AmbientSoundServerComponent(AmbientSoundServerComponent const&)            = delete;
    AmbientSoundServerComponent()                                              = delete;

public:
    /**
     * @symbol ??4AmbientSoundServerComponent\@\@QEAAAEAV0\@$$QEAV0\@\@Z
     */
    MCAPI class AmbientSoundServerComponent& operator=(class AmbientSoundServerComponent&&); // NOLINT
    /**
     * @symbol ??1AmbientSoundServerComponent\@\@QEAA\@XZ
     */
    MCAPI ~AmbientSoundServerComponent(); // NOLINT
};
