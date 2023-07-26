#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/json/JsonSchemaObjectNode.h"

// auto generated forward declare list
// clang-format off
namespace JsonUtil { class EmptyClass; }
// clang-format on

class PlayGoal {
public:
    // PlayGoal inner types declare
    // clang-format off
    class PlayDefinition;
    // clang-format on

    // PlayGoal inner types define
    class PlayDefinition {

    public:
        // prevent constructor by default
        PlayDefinition& operator=(PlayDefinition const&) = delete;
        PlayDefinition(PlayDefinition const&)            = delete;
        PlayDefinition()                                 = delete;

    public:
        /**
         * @symbol ?initialize\@PlayDefinition\@PlayGoal\@\@QEBAXAEAVEntityContext\@\@AEAV2\@\@Z
         */
        MCAPI void initialize(class EntityContext&, class PlayGoal&) const; // NOLINT
        /**
         * @symbol
         * ?buildSchema\@PlayDefinition\@PlayGoal\@\@SAXAEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@AEAV?$shared_ptr\@V?$JsonSchemaObjectNode\@VEmptyClass\@JsonUtil\@\@VPlayDefinition\@PlayGoal\@\@\@JsonUtil\@\@\@4\@\@Z
         */
        MCAPI static void
        buildSchema(std::string const&, class std::shared_ptr<class JsonUtil::JsonSchemaObjectNode<class JsonUtil::EmptyClass, class PlayGoal::PlayDefinition>>&); // NOLINT
        /**
         * @symbol ?getStrictParsingVersion\@PlayDefinition\@PlayGoal\@\@SA?AVSemVersion\@\@XZ
         */
        MCAPI static class SemVersion getStrictParsingVersion(); // NOLINT
    };

public:
    // prevent constructor by default
    PlayGoal& operator=(PlayGoal const&) = delete;
    PlayGoal(PlayGoal const&)            = delete;
    PlayGoal()                           = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?canUse\@PlayGoal\@\@UEAA_NXZ
     */
    virtual bool canUse(); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?canContinueToUse\@PlayGoal\@\@UEAA_NXZ
     */
    virtual bool canContinueToUse(); // NOLINT
    /**
     * @vftbl 3
     * @symbol __unk_vfn_3
     */
    virtual void __unk_vfn_3(); // NOLINT
    /**
     * @vftbl 4
     * @symbol ?start\@PlayGoal\@\@UEAAXXZ
     */
    virtual void start(); // NOLINT
    /**
     * @vftbl 5
     * @symbol ?stop\@PlayGoal\@\@UEAAXXZ
     */
    virtual void stop(); // NOLINT
    /**
     * @vftbl 6
     * @symbol ?tick\@PlayGoal\@\@UEAAXXZ
     */
    virtual void tick(); // NOLINT
    /**
     * @vftbl 7
     * @symbol
     * ?appendDebugInfo\@PlayGoal\@\@UEBAXAEAV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    virtual void appendDebugInfo(std::string&) const; // NOLINT
    /**
     * @symbol ??0PlayGoal\@\@QEAA\@AEAVMob\@\@\@Z
     */
    MCAPI PlayGoal(class Mob&); // NOLINT
};
