#pragma once

#include "mc/_HeaderOutputPredefine.h"

namespace BlockDescriptorSerializer {

struct StateNameProxy {

public:
    // prevent constructor by default
    StateNameProxy& operator=(StateNameProxy const&) = delete;
    StateNameProxy(StateNameProxy const&)            = delete;
    StateNameProxy()                                 = delete;

public:
    /**
     * @symbol ??1StateNameProxy\@BlockDescriptorSerializer\@\@QEAA\@XZ
     */
    MCAPI ~StateNameProxy(); // NOLINT
    /**
     * @symbol ?bindType\@StateNameProxy\@BlockDescriptorSerializer\@\@SAXXZ
     */
    MCAPI static void bindType(); // NOLINT
    /**
     * @symbol
     * ?constructFromString\@StateNameProxy\@BlockDescriptorSerializer\@\@SA?AU12\@AEBV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@\@Z
     */
    MCAPI static struct BlockDescriptorSerializer::StateNameProxy constructFromString(std::string const&); // NOLINT
};

}; // namespace BlockDescriptorSerializer
