#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/levelgen/structure/StructureFeature.h"

class WoodlandMansionFeature : public ::StructureFeature {

public:
    // prevent constructor by default
    WoodlandMansionFeature& operator=(WoodlandMansionFeature const&) = delete;
    WoodlandMansionFeature(WoodlandMansionFeature const&)            = delete;
    WoodlandMansionFeature()                                         = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 2
     * @symbol ?shouldPostProcessMobs\@WoodlandMansionFeature\@\@UEBA_NXZ
     */
    virtual bool shouldPostProcessMobs() const; // NOLINT
    /**
     * @vftbl 3
     * @symbol
     * ?getNearestGeneratedFeature\@WoodlandMansionFeature\@\@UEAA_NAEAVDimension\@\@AEBVBiomeSource\@\@AEBVBlockPos\@\@AEAV4\@AEBVIPreliminarySurfaceProvider\@\@_N\@Z
     */
    virtual bool getNearestGeneratedFeature(
        class Dimension&,
        class BiomeSource const&,
        class BlockPos const&,
        class BlockPos&,
        class IPreliminarySurfaceProvider const&,
        bool
    ); // NOLINT
    /**
     * @vftbl 5
     * @symbol
     * ?isFeatureChunk\@WoodlandMansionFeature\@\@MEAA_NAEBVBiomeSource\@\@AEAVRandom\@\@AEBVChunkPos\@\@IAEBVIPreliminarySurfaceProvider\@\@AEBVDimension\@\@\@Z
     */
    virtual bool
    isFeatureChunk(class BiomeSource const&, class Random&, class ChunkPos const&, unsigned int, class IPreliminarySurfaceProvider const&, class Dimension const&); // NOLINT
    /**
     * @vftbl 6
     * @symbol
     * ?createStructureStart\@WoodlandMansionFeature\@\@MEAA?AV?$unique_ptr\@VStructureStart\@\@U?$default_delete\@VStructureStart\@\@\@std\@\@\@std\@\@AEAVDimension\@\@AEBVBiomeSource\@\@AEAVRandom\@\@AEBVChunkPos\@\@AEBVIPreliminarySurfaceProvider\@\@\@Z
     */
    virtual std::unique_ptr<class StructureStart>
    createStructureStart(class Dimension&, class BiomeSource const&, class Random&, class ChunkPos const&, class IPreliminarySurfaceProvider const&); // NOLINT
    /**
     * @symbol ??0WoodlandMansionFeature\@\@QEAA\@I\@Z
     */
    MCAPI WoodlandMansionFeature(unsigned int); // NOLINT
};
