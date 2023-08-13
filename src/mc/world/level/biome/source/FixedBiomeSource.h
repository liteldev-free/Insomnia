#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/levelgen/v1/BiomeSource.h"

class FixedBiomeSource : public ::BiomeSource {

public:
    // prevent constructor by default
    FixedBiomeSource& operator=(FixedBiomeSource const&) = delete;
    FixedBiomeSource(FixedBiomeSource const&)            = delete;
    FixedBiomeSource()                                   = delete;

public:
    // NOLINTBEGIN
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0();
    /**
     * @vftbl 1
     * @symbol ?fillBiomes\@FixedBiomeSource\@\@UEBAXAEAVLevelChunk\@\@AEBVChunkLocalNoiseCache\@\@\@Z
     */
    virtual void fillBiomes(class LevelChunk&, class ChunkLocalNoiseCache const&) const;
    /**
     * @vftbl 2
     * @symbol ?getBiomeArea\@FixedBiomeSource\@\@UEBA?AVBiomeArea\@\@AEBVBoundingBox\@\@I\@Z
     */
    virtual class BiomeArea getBiomeArea(class BoundingBox const&, unsigned int) const;
    /**
     * @vftbl 3
     * @symbol ?getBiomeArea\@FixedBiomeSource\@\@UEBA?AVBiomeArea\@\@AEBVBoundingBox\@\@IAEBUGetBiomeOptions\@\@\@Z
     */
    virtual class BiomeArea getBiomeArea(class BoundingBox const&, unsigned int, struct GetBiomeOptions const&) const;
    /**
     * @vftbl 4
     * @symbol ?containsOnly\@FixedBiomeSource\@\@UEBA_NHHHHV?$span\@$$CB_K$0?0\@gsl\@\@\@Z
     */
    virtual bool containsOnly(int, int, int, int, class gsl::span<uint64_t const>) const;
#ifdef ENABLE_VIRTUAL_FAKESYMBOL_FIXEDBIOMESOURCE
    /**
     * @symbol ?getBiome\@FixedBiomeSource\@\@UEBAPEBVBiome\@\@AEBVBlockPos\@\@\@Z
     */
    MCVAPI class Biome const* getBiome(class BlockPos const&) const;
    /**
     * @symbol ?getBiome\@FixedBiomeSource\@\@UEBAPEBVBiome\@\@AEBUGetBiomeOptions\@\@\@Z
     */
    MCVAPI class Biome const* getBiome(struct GetBiomeOptions const&) const;
    /**
     * @symbol ?getBiome\@FixedBiomeSource\@\@UEBAPEBVBiome\@\@HHH\@Z
     */
    MCVAPI class Biome const* getBiome(int, int, int) const;
#endif
    /**
     * @symbol ??0FixedBiomeSource\@\@QEAA\@AEBVBiome\@\@\@Z
     */
    MCAPI FixedBiomeSource(class Biome const&);
    // NOLINTEND
};
