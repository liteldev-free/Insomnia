#pragma once

#include "mc/_HeaderOutputPredefine.h"

class GameEventListenerRegistry {

public:
    // prevent constructor by default
    GameEventListenerRegistry& operator=(GameEventListenerRegistry const&) = delete;
    GameEventListenerRegistry(GameEventListenerRegistry const&)            = delete;
    GameEventListenerRegistry()                                            = delete;

public:
    /**
     * @symbol
     * ?getListeners\@GameEventListenerRegistry\@\@QEBA?AV?$vector\@V?$reference_wrapper\@VGameEventListener\@\@\@std\@\@V?$allocator\@V?$reference_wrapper\@VGameEventListener\@\@\@std\@\@\@2\@\@std\@\@XZ
     */
    MCAPI std::vector<class std::reference_wrapper<class GameEventListener>> getListeners() const; // NOLINT
    /**
     * @symbol
     * ?registerListener\@GameEventListenerRegistry\@\@QEAA?AV?$final_action\@V?$function\@$$A6AXXZ\@std\@\@\@gsl\@\@AEAVGameEventListener\@\@\@Z
     */
    MCAPI class gsl::final_action<class std::function<void(void)>> registerListener(class GameEventListener&); // NOLINT
};
