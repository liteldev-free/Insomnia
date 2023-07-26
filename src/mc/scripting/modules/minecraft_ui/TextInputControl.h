#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated forward declare list
// clang-format off
namespace Json { class Value; }
// clang-format on

namespace ScriptModuleMinecraftServerUI {

class TextInputControl {

public:
    // prevent constructor by default
    TextInputControl& operator=(TextInputControl const&) = delete;
    TextInputControl(TextInputControl const&)            = delete;
    TextInputControl()                                   = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?getJson\@TextInputControl\@ScriptModuleMinecraftServerUI\@\@UEBA?AVValue\@Json\@\@XZ
     */
    virtual class Json::Value getJson() const; // NOLINT
    /**
     * @symbol
     * ??0TextInputControl\@ScriptModuleMinecraftServerUI\@\@QEAA\@VValue\@Json\@\@0V?$optional\@V?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@std\@\@\@Z
     */
    MCAPI TextInputControl(class Json::Value, class Json::Value, class std::optional<std::string>); // NOLINT
};

}; // namespace ScriptModuleMinecraftServerUI
