#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/json/JsonSchemaObjectNode.h"

// auto generated forward declare list
// clang-format off
namespace JsonUtil { class EmptyClass; }
// clang-format on

class SlimeKeepOnJumpingDefinition {

public:
    // prevent constructor by default
    SlimeKeepOnJumpingDefinition& operator=(SlimeKeepOnJumpingDefinition const&) = delete;
    SlimeKeepOnJumpingDefinition(SlimeKeepOnJumpingDefinition const&)            = delete;

public:
    /**
     * @symbol ??0SlimeKeepOnJumpingDefinition\@\@QEAA\@XZ
     */
    MCAPI SlimeKeepOnJumpingDefinition(); // NOLINT
    /**
     * @symbol ?initialize\@SlimeKeepOnJumpingDefinition\@\@QEBAXAEAVEntityContext\@\@AEAVSlimeKeepOnJumpingGoal\@\@\@Z
     */
    MCAPI void initialize(class EntityContext&, class SlimeKeepOnJumpingGoal&) const; // NOLINT
    /**
     * @symbol
     * ?buildSchema\@SlimeKeepOnJumpingDefinition\@\@SAXAEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@AEAV?$shared_ptr\@V?$JsonSchemaObjectNode\@VEmptyClass\@JsonUtil\@\@VSlimeKeepOnJumpingDefinition\@\@\@JsonUtil\@\@\@3\@\@Z
     */
    MCAPI static void
    buildSchema(std::string const&, class std::shared_ptr<class JsonUtil::JsonSchemaObjectNode<class JsonUtil::EmptyClass, class SlimeKeepOnJumpingDefinition>>&); // NOLINT
};
