#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/filters/FilterTest.h"
#include "mc/world/filters/SimpleBoolFilterTest.h"

// auto generated forward declare list
// clang-format off
namespace Json { class Value; }
// clang-format on

class ActorIsRaiderTest : public ::SimpleBoolFilterTest {

public:
    // prevent constructor by default
    ActorIsRaiderTest& operator=(ActorIsRaiderTest const&) = delete;
    ActorIsRaiderTest(ActorIsRaiderTest const&)            = delete;
    ActorIsRaiderTest()                                    = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?setup\@SimpleBoolFilterTest\@\@UEAA_NAEBUDefinition\@FilterTest\@\@AEBUFilterInputs\@\@\@Z
     */
    virtual bool setup(struct FilterTest::Definition const&, struct FilterInputs const&); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?evaluate\@ActorIsRaiderTest\@\@UEBA_NAEBUFilterContext\@\@\@Z
     */
    virtual bool evaluate(struct FilterContext const&) const; // NOLINT
    /**
     * @vftbl 3
     * @symbol __unk_vfn_3
     */
    virtual void __unk_vfn_3(); // NOLINT
    /**
     * @vftbl 4
     * @symbol ?getName\@ActorIsRaiderTest\@\@UEBA?AV?$basic_string_view\@DU?$char_traits\@D\@std\@\@\@std\@\@XZ
     */
    virtual class std::basic_string_view<char, struct std::char_traits<char>> getName() const; // NOLINT
    /**
     * @vftbl 5
     * @symbol ?_serializeDomain\@FilterTest\@\@MEBA?AVValue\@Json\@\@XZ
     */
    virtual class Json::Value _serializeDomain() const; // NOLINT
    /**
     * @vftbl 6
     * @symbol ?_serializeValue\@SimpleBoolFilterTest\@\@MEBA?AVValue\@Json\@\@XZ
     */
    virtual class Json::Value _serializeValue() const; // NOLINT
};
