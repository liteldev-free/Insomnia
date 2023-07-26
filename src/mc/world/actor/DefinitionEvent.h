#pragma once

#include "mc/_HeaderOutputPredefine.h"

class DefinitionEvent {

public:
    // prevent constructor by default
    DefinitionEvent() = delete;

public:
    /**
     * @symbol ??0DefinitionEvent\@\@QEAA\@AEBV0\@\@Z
     */
    MCAPI DefinitionEvent(class DefinitionEvent const&); // NOLINT
    /**
     * @symbol ??0DefinitionEvent\@\@QEAA\@$$QEAV0\@\@Z
     */
    MCAPI DefinitionEvent(class DefinitionEvent&&); // NOLINT
    /**
     * @symbol
     * ?evaluateEvent\@DefinitionEvent\@\@QEBAXAEAVRenderParams\@\@AEAV?$vector\@UDefinitionModifier\@\@V?$allocator\@UDefinitionModifier\@\@\@std\@\@\@std\@\@\@Z
     */
    MCAPI void evaluateEvent(class RenderParams&, std::vector<struct DefinitionModifier>&) const; // NOLINT
    /**
     * @symbol ??4DefinitionEvent\@\@QEAAAEAV0\@AEBV0\@\@Z
     */
    MCAPI class DefinitionEvent& operator=(class DefinitionEvent const&); // NOLINT
    /**
     * @symbol ??1DefinitionEvent\@\@QEAA\@XZ
     */
    MCAPI ~DefinitionEvent(); // NOLINT
};
