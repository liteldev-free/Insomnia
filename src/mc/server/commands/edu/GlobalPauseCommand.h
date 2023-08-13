#pragma once

#include "mc/_HeaderOutputPredefine.h"

// auto generated inclusion list
#include "mc/server/commands/ServerCommand.h"

class GlobalPauseCommand : public ::ServerCommand {

public:
    // prevent constructor by default
    GlobalPauseCommand& operator=(GlobalPauseCommand const&) = delete;
    GlobalPauseCommand(GlobalPauseCommand const&)            = delete;
    GlobalPauseCommand()                                     = delete;

public:
    // NOLINTBEGIN
    /**
     * @vftbl 0
     * @symbol __unk_vfn_0
     */
    virtual void __unk_vfn_0();
    /**
     * @vftbl 1
     * @symbol ?collectOptionalArguments\@Command\@\@MEAA_NXZ
     */
    virtual bool collectOptionalArguments();
    /**
     * @vftbl 2
     * @symbol ?execute\@GlobalPauseCommand\@\@UEBAXAEBVCommandOrigin\@\@AEAVCommandOutput\@\@\@Z
     */
    virtual void execute(class CommandOrigin const&, class CommandOutput&) const;
    /**
     * @symbol ?setup\@GlobalPauseCommand\@\@SAXAEAVCommandRegistry\@\@\@Z
     */
    MCAPI static void setup(class CommandRegistry&);
    // NOLINTEND
};
