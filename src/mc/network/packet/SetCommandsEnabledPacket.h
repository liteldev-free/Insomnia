#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/core/common/bedrock/Result.h"
#include "mc/network/packet/Packet.h"

class SetCommandsEnabledPacket : public ::Packet {

public:
    // prevent constructor by default
    SetCommandsEnabledPacket& operator=(SetCommandsEnabledPacket const&) = delete;
    SetCommandsEnabledPacket(SetCommandsEnabledPacket const&)            = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?getId\@SetCommandsEnabledPacket\@\@UEBA?AW4MinecraftPacketIds\@\@XZ
     */
    virtual enum class MinecraftPacketIds getId() const; // NOLINT
    /**
     * @vftbl 2
     * @symbol
     * ?getName\@SetCommandsEnabledPacket\@\@UEBA?AV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@XZ
     */
    virtual std::string getName() const; // NOLINT
    /**
     * @vftbl 3
     * @symbol ?write\@SetCommandsEnabledPacket\@\@UEBAXAEAVBinaryStream\@\@\@Z
     */
    virtual void write(class BinaryStream&) const; // NOLINT
    /**
     * @vftbl 7
     * @symbol
     * ?_read\@SetCommandsEnabledPacket\@\@EEAA?AV?$Result\@XVerror_code\@std\@\@\@Bedrock\@\@AEAVReadOnlyBinaryStream\@\@\@Z
     */
    virtual class Bedrock::Result<void, class std::error_code> _read(class ReadOnlyBinaryStream&); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_SETCOMMANDSENABLEDPACKET
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~SetCommandsEnabledPacket(); // NOLINT
#endif
    /**
     * @symbol ??0SetCommandsEnabledPacket\@\@QEAA\@XZ
     */
    MCAPI SetCommandsEnabledPacket(); // NOLINT
    /**
     * @symbol ??0SetCommandsEnabledPacket\@\@QEAA\@_N\@Z
     */
    MCAPI SetCommandsEnabledPacket(bool); // NOLINT
};
