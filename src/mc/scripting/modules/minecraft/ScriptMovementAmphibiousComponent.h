#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/external/scripting/ClassBindingBuilder.h"
#include "mc/external/scripting/Result.h"
#include "mc/scripting/modules/minecraft/MovementScriptActorComponent.h"

namespace ScriptModuleMinecraft {

class ScriptMovementAmphibiousComponent : public ::ScriptModuleMinecraft::MovementScriptActorComponent {

public:
    // prevent constructor by default
    ScriptMovementAmphibiousComponent& operator=(ScriptMovementAmphibiousComponent const&) = delete;
    ScriptMovementAmphibiousComponent(ScriptMovementAmphibiousComponent const&)            = delete;
    ScriptMovementAmphibiousComponent()                                                    = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_SCRIPTMODULEMINECRAFT_SCRIPTMOVEMENTAMPHIBIOUSCOMPONENT
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~ScriptMovementAmphibiousComponent(); // NOLINT
#endif
    /**
     * @symbol
     * ?bind\@ScriptMovementAmphibiousComponent\@ScriptModuleMinecraft\@\@SA?AV?$ClassBindingBuilder\@VScriptMovementAmphibiousComponent\@ScriptModuleMinecraft\@\@\@Scripting\@\@XZ
     */
    MCAPI static class Scripting::ClassBindingBuilder<class ScriptModuleMinecraft::ScriptMovementAmphibiousComponent>
    bind(); // NOLINT
    /**
     * @symbol
     * ?bindV010\@ScriptMovementAmphibiousComponent\@ScriptModuleMinecraft\@\@SA?AV?$ClassBindingBuilder\@VScriptMovementAmphibiousComponent\@ScriptModuleMinecraft\@\@\@Scripting\@\@XZ
     */
    MCAPI static class Scripting::ClassBindingBuilder<class ScriptModuleMinecraft::ScriptMovementAmphibiousComponent>
    bindV010(); // NOLINT
    /**
     * @symbol ?ComponentId\@ScriptMovementAmphibiousComponent\@ScriptModuleMinecraft\@\@2PEBDEB
     */
    MCAPI static char const* ComponentId; // NOLINT
};

}; // namespace ScriptModuleMinecraft
