#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/json/JsonSchemaObjectNode.h"

// auto generated forward declare list
// clang-format off
namespace JsonUtil { class EmptyClass; }
// clang-format on

class FlockingDefinition {

public:
    // prevent constructor by default
    FlockingDefinition& operator=(FlockingDefinition const&) = delete;
    FlockingDefinition(FlockingDefinition const&)            = delete;

public:
    /**
     * @symbol ??0FlockingDefinition\@\@QEAA\@XZ
     */
    MCAPI FlockingDefinition(); // NOLINT
    /**
     * @symbol ?initialize\@FlockingDefinition\@\@QEBAXAEAVEntityContext\@\@AEAVFlockingComponent\@\@\@Z
     */
    MCAPI void initialize(class EntityContext&, class FlockingComponent&) const; // NOLINT
    /**
     * @symbol
     * ?buildSchema\@FlockingDefinition\@\@SAXAEAV?$shared_ptr\@V?$JsonSchemaObjectNode\@VEmptyClass\@JsonUtil\@\@VFlockingDefinition\@\@\@JsonUtil\@\@\@std\@\@\@Z
     */
    MCAPI static void
    buildSchema(class std::shared_ptr<
                class JsonUtil::JsonSchemaObjectNode<class JsonUtil::EmptyClass, class FlockingDefinition>>&); // NOLINT
};
