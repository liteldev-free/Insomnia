#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/deps/core/common/bedrock/Result.h"
#include "mc/network/packet/Packet.h"

class CameraPresetsPacket : public ::Packet {

public:
    // prevent constructor by default
    CameraPresetsPacket& operator=(CameraPresetsPacket const&) = delete;
    CameraPresetsPacket(CameraPresetsPacket const&)            = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?getId\@CameraPresetsPacket\@\@UEBA?AW4MinecraftPacketIds\@\@XZ
     */
    virtual enum class MinecraftPacketIds getId() const; // NOLINT
    /**
     * @vftbl 2
     * @symbol
     * ?getName\@CameraPresetsPacket\@\@UEBA?AV?$basic_string\@DU?$char_traits\@D\@std\@\@V?$allocator\@D\@2\@\@std\@\@XZ
     */
    virtual std::string getName() const; // NOLINT
    /**
     * @vftbl 3
     * @symbol ?write\@CameraPresetsPacket\@\@UEBAXAEAVBinaryStream\@\@\@Z
     */
    virtual void write(class BinaryStream&) const; // NOLINT
    /**
     * @vftbl 4
     * @symbol
     * ?read\@CameraPresetsPacket\@\@UEAA?AV?$Result\@XVerror_code\@std\@\@\@Bedrock\@\@AEAVReadOnlyBinaryStream\@\@\@Z
     */
    virtual class Bedrock::Result<void, class std::error_code> read(class ReadOnlyBinaryStream&); // NOLINT
    /**
     * @vftbl 7
     * @symbol
     * ?_read\@CameraPresetsPacket\@\@EEAA?AV?$Result\@XVerror_code\@std\@\@\@Bedrock\@\@AEAVReadOnlyBinaryStream\@\@\@Z
     */
    virtual class Bedrock::Result<void, class std::error_code> _read(class ReadOnlyBinaryStream&); // NOLINT
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_CAMERAPRESETSPACKET
    /**
     * @symbol __unk_destructor_-1
     */
    MCVAPI ~CameraPresetsPacket(); // NOLINT
#endif
    /**
     * @symbol ??0CameraPresetsPacket\@\@QEAA\@AEBVCameraPresets\@\@\@Z
     */
    MCAPI CameraPresetsPacket(class CameraPresets const&); // NOLINT
    /**
     * @symbol ??0CameraPresetsPacket\@\@QEAA\@XZ
     */
    MCAPI CameraPresetsPacket(); // NOLINT
};
