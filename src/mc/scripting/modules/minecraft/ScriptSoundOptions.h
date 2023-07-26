#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/external/scripting/ClassBindingBuilder.h"

// auto generated forward declare list
// clang-format off
class Vec3;
// clang-format on

namespace ScriptModuleMinecraft {

struct ScriptSoundOptions {

public:
    // prevent constructor by default
    ScriptSoundOptions(ScriptSoundOptions const&) = delete;
    ScriptSoundOptions()                          = delete;

public:
    /**
     * @symbol ?getLocation\@ScriptSoundOptions\@ScriptModuleMinecraft\@\@QEBA?AVVec3\@\@XZ
     */
    MCAPI class Vec3 getLocation() const; // NOLINT
    /**
     * @symbol ?getPitch\@ScriptSoundOptions\@ScriptModuleMinecraft\@\@QEBAMXZ
     */
    MCAPI float getPitch() const; // NOLINT
    /**
     * @symbol ?getVolume\@ScriptSoundOptions\@ScriptModuleMinecraft\@\@QEBAMXZ
     */
    MCAPI float getVolume() const; // NOLINT
    /**
     * @symbol ??4ScriptSoundOptions\@ScriptModuleMinecraft\@\@QEAAAEAU01\@$$QEAU01\@\@Z
     */
    MCAPI struct ScriptModuleMinecraft::ScriptSoundOptions&
    operator=(struct ScriptModuleMinecraft::ScriptSoundOptions&&); // NOLINT
    /**
     * @symbol ??4ScriptSoundOptions\@ScriptModuleMinecraft\@\@QEAAAEAU01\@AEBU01\@\@Z
     */
    MCAPI struct ScriptModuleMinecraft::ScriptSoundOptions&
    operator=(struct ScriptModuleMinecraft::ScriptSoundOptions const&); // NOLINT
    /**
     * @symbol
     * ?bindV010\@ScriptSoundOptions\@ScriptModuleMinecraft\@\@SA?AV?$ClassBindingBuilder\@UScriptSoundOptions\@ScriptModuleMinecraft\@\@\@Scripting\@\@XZ
     */
    MCAPI static class Scripting::ClassBindingBuilder<struct ScriptModuleMinecraft::ScriptSoundOptions>
    bindV010(); // NOLINT
};

}; // namespace ScriptModuleMinecraft
