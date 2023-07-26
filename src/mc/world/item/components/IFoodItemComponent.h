#pragma once

#include "mc/_HeaderOutputPredefine.h"

class IFoodItemComponent {

public:
    // prevent constructor by default
    IFoodItemComponent& operator=(IFoodItemComponent const&) = delete;
    IFoodItemComponent(IFoodItemComponent const&)            = delete;
    IFoodItemComponent()                                     = delete;

public:
    /**
     * @symbol ?CAN_ALWAYS_EAT\@IFoodItemComponent\@\@2QBDB
     */
    MCAPI static char const CAN_ALWAYS_EAT[]; // NOLINT
    /**
     * @symbol ?NUTRITION\@IFoodItemComponent\@\@2QBDB
     */
    MCAPI static char const NUTRITION[]; // NOLINT
    /**
     * @symbol ?SATURATION_MODIFIER\@IFoodItemComponent\@\@2QBDB
     */
    MCAPI static char const SATURATION_MODIFIER[]; // NOLINT
};
