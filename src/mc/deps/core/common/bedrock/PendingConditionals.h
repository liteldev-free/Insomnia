#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/core/common/bedrock/EnableNonOwnerReferences.h"

// auto generated forward declare list
// clang-format off
namespace Bedrock { class EnableNonOwnerReferences; }
// clang-format on

namespace Bedrock::Threading {

class PendingConditionals : public ::Bedrock::EnableNonOwnerReferences {
public:
    // prevent constructor by default
    PendingConditionals& operator=(PendingConditionals const&);
    PendingConditionals(PendingConditionals const&);
    PendingConditionals();

public:
    // NOLINTBEGIN
    // vIndex: 0, symbol: __gen_??1PendingConditionals@Threading@Bedrock@@UEAA@XZ
    virtual ~PendingConditionals() = default;

    // NOLINTEND
};

}; // namespace Bedrock::Threading