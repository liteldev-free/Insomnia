#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/world/level/Command.h"

class StopCommand : public ::Command {

public:
    // prevent constructor by default
    StopCommand& operator=(StopCommand const&) = delete;
    StopCommand(StopCommand const&)            = delete;
    StopCommand()                              = delete;

public:
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0(); // NOLINT
    /**
     * @vftbl 1
     * @symbol ?execute\@StopCommand\@\@UEBAXAEBVCommandOrigin\@\@AEAVCommandOutput\@\@\@Z
     */
    virtual void execute(class CommandOrigin const&, class CommandOutput&) const; // NOLINT
    /**
     * @symbol ?setup\@StopCommand\@\@SAXAEAVCommandRegistry\@\@AEAVDedicatedServer\@\@\@Z
     */
    MCAPI static void setup(class CommandRegistry&, class DedicatedServer&); // NOLINT

    // private:

private:
    /**
     * @symbol ?mServer\@StopCommand\@\@0PEAVDedicatedServer\@\@EA
     */
    MCAPI static class DedicatedServer* mServer; // NOLINT
};
