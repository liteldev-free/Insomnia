#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/core/common/bedrock/Result.h"
#include "mc/network/packet/EntityServerPacket.h"

class AddEntityPacket : public ::EntityServerPacket {

public:
    // prevent constructor by default
    AddEntityPacket& operator=(AddEntityPacket const&) = delete;
    AddEntityPacket(AddEntityPacket const&)            = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?getId\@AddEntityPacket\@\@UEBA?AW4MinecraftPacketIds\@\@XZ
     */
    virtual enum class MinecraftPacketIds getId() const; // NOLINT
    /**
     * @vftbl 2
     * @symbol
     * ?getName\@AddEntityPacket\@\@UEBA?AV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@XZ
     */
    virtual std::string getName() const; // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_ADDENTITYPACKET
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~AddEntityPacket(); // NOLINT
#endif
    /**
     * @symbol ??0AddEntityPacket\@\@QEAA\@XZ
     */
    MCAPI AddEntityPacket(); // NOLINT
};
