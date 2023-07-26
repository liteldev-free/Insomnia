#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/external/scripting/ClassBindingBuilder.h"

namespace ScriptModuleMinecraft {

struct ScriptWeatherChangedAfterEvent {

public:
    // prevent constructor by default
    ScriptWeatherChangedAfterEvent& operator=(ScriptWeatherChangedAfterEvent const&) = delete;
    ScriptWeatherChangedAfterEvent(ScriptWeatherChangedAfterEvent const&)            = delete;
    ScriptWeatherChangedAfterEvent()                                                 = delete;

public:
    /**
     * @symbol ??4ScriptWeatherChangedAfterEvent\@ScriptModuleMinecraft\@\@QEAAAEAU01\@$$QEAU01\@\@Z
     */
    MCAPI struct ScriptModuleMinecraft::ScriptWeatherChangedAfterEvent&
    operator=(struct ScriptModuleMinecraft::ScriptWeatherChangedAfterEvent&&); // NOLINT
    /**
     * @symbol
     * ?bind\@ScriptWeatherChangedAfterEvent\@ScriptModuleMinecraft\@\@SA?AV?$ClassBindingBuilder\@UScriptWeatherChangedAfterEvent\@ScriptModuleMinecraft\@\@\@Scripting\@\@XZ
     */
    MCAPI static class Scripting::ClassBindingBuilder<struct ScriptModuleMinecraft::ScriptWeatherChangedAfterEvent>
    bind(); // NOLINT
    /**
     * @symbol
     * ?bindV010\@ScriptWeatherChangedAfterEvent\@ScriptModuleMinecraft\@\@SA?AV?$ClassBindingBuilder\@UScriptWeatherChangedAfterEvent\@ScriptModuleMinecraft\@\@\@Scripting\@\@XZ
     */
    MCAPI static class Scripting::ClassBindingBuilder<struct ScriptModuleMinecraft::ScriptWeatherChangedAfterEvent>
    bindV010(); // NOLINT
};

}; // namespace ScriptModuleMinecraft
