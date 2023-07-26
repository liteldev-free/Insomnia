#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/entity/components/MoveControlDescription.h"

class AmphibiousMoveControlDescription : public ::MoveControlDescription {

public:
    // prevent constructor by default
    AmphibiousMoveControlDescription& operator=(AmphibiousMoveControlDescription const&) = delete;
    AmphibiousMoveControlDescription(AmphibiousMoveControlDescription const&)            = delete;
    AmphibiousMoveControlDescription()                                                   = delete;

public:
    /**
     * @vftbl 0
     * @symbol ?getJsonName\@AmphibiousMoveControlDescription\@\@UEBAPEBDXZ
     */
    virtual char const* getJsonName() const; // NOLINT
    /**
     * @vftbl 1
     * @symbol __unk_vfn_1
     */
    virtual void __unk_vfn_1(); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?deserializeData\@MoveControlDescription\@\@UEAAXUDeserializeDataParams\@\@\@Z
     */
    virtual void deserializeData(struct DeserializeDataParams); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_AMPHIBIOUSMOVECONTROLDESCRIPTION
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~AmphibiousMoveControlDescription(); // NOLINT
#endif
};
