#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/json/JsonSchemaObjectNode.h"

// auto generated forward declare list
// clang-format off
namespace JsonUtil { class EmptyClass; }
// clang-format on

class AgeableDefinition {

public:
    // prevent constructor by default
    AgeableDefinition& operator=(AgeableDefinition const&) = delete;
    AgeableDefinition(AgeableDefinition const&)            = delete;
    AgeableDefinition()                                    = delete;

public:
    /**
     * @symbol ?addDropItem\@AgeableDefinition\@\@QEAAXAEBVItemDescriptor\@\@\@Z
     */
    MCAPI void addDropItem(class ItemDescriptor const&); // NOLINT
    /**
     * @symbol ?addFeedItem\@AgeableDefinition\@\@QEAAXAEBUActorDefinitionFeedItem\@\@\@Z
     */
    MCAPI void addFeedItem(struct ActorDefinitionFeedItem const&); // NOLINT
    /**
     * @symbol
     * ?addFeedItemByName\@AgeableDefinition\@\@QEAAXAEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    MCAPI void addFeedItemByName(std::string const&); // NOLINT
    /**
     * @symbol ?canGrowUp\@AgeableDefinition\@\@QEBA_NXZ
     */
    MCAPI bool canGrowUp() const; // NOLINT
    /**
     * @symbol ?getTicksAsBaby\@AgeableDefinition\@\@QEBAHXZ
     */
    MCAPI int getTicksAsBaby() const; // NOLINT
    /**
     * @symbol ?initialize\@AgeableDefinition\@\@QEBAXAEAVEntityContext\@\@AEAVAgeableComponent\@\@\@Z
     */
    MCAPI void initialize(class EntityContext&, class AgeableComponent&) const; // NOLINT
    /**
     * @symbol
     * ?buildSchema\@AgeableDefinition\@\@SAXAEAV?$shared_ptr\@V?$JsonSchemaObjectNode\@VEmptyClass\@JsonUtil\@\@VAgeableDefinition\@\@\@JsonUtil\@\@\@std\@\@\@Z
     */
    MCAPI static void
    buildSchema(class std::shared_ptr<
                class JsonUtil::JsonSchemaObjectNode<class JsonUtil::EmptyClass, class AgeableDefinition>>&); // NOLINT
};
