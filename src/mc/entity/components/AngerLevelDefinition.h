#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/json/JsonSchemaObjectNode.h"

// auto generated forward declare list
// clang-format off
namespace JsonUtil { class EmptyClass; }
// clang-format on

class AngerLevelDefinition {

public:
    // prevent constructor by default
    AngerLevelDefinition& operator=(AngerLevelDefinition const&) = delete;
    AngerLevelDefinition(AngerLevelDefinition const&)            = delete;
    AngerLevelDefinition()                                       = delete;

public:
    /**
     * @symbol ?addOnIncreaseSoundDefinition\@AngerLevelDefinition\@\@QEAAXAEBVSoundDefinition\@\@\@Z
     */
    MCAPI void addOnIncreaseSoundDefinition(class SoundDefinition const&); // NOLINT
    /**
     * @symbol ?initialize\@AngerLevelDefinition\@\@QEBAXAEAVEntityContext\@\@AEAVAngerLevelComponent\@\@\@Z
     */
    MCAPI void initialize(class EntityContext&, class AngerLevelComponent&) const; // NOLINT
    /**
     * @symbol
     * ?buildSchema\@AngerLevelDefinition\@\@SAXAEAV?$shared_ptr\@V?$JsonSchemaObjectNode\@VEmptyClass\@JsonUtil\@\@VAngerLevelDefinition\@\@\@JsonUtil\@\@\@std\@\@\@Z
     */
    MCAPI static void buildSchema(class std::shared_ptr<class JsonUtil::JsonSchemaObjectNode<
                                      class JsonUtil::EmptyClass,
                                      class AngerLevelDefinition>>&); // NOLINT
};
