#include "ll/api/plugin/Manifest.h"
#include "ll/api/plugin/PluginManagerRegistry.h"
#include "ll/core/command/BuiltinCommands.h"

#include "ll/api/command/CommandHandle.h"
#include "ll/api/command/CommandRegistrar.h"
#include "ll/api/i18n/I18n.h"

#include "ll/api/plugin/Plugin.h"
#include "ll/api/service/Bedrock.h"
#include "ll/core/plugin/PluginRegistrar.h"
#include "mc/server/commands/CommandOrigin.h"
#include "mc/server/commands/CommandOutput.h"
#include "mc/server/commands/CommandPermissionLevel.h"
#include "mc/server/commands/CommandRegistry.h"
#include <string>
#include <string_view>
#include <vector>


namespace ll::command {
using namespace ll::i18n_literals;

enum LeviCommandOperation : int {
    unload,
    reload,
    reactivate,
};
enum LeviCommandOperation2 : int {
    enable,
    disable,
    show,
};
struct LeviCommand {
    LeviCommandOperation operation;
    std::string          plugin;
};
struct LeviCommand2 {
    LeviCommandOperation2 operation;
    std::string           plugin;
};
struct LeviCommand3 {
    std::string plugin;
};

void registerPluginManageCommand() {
    auto& cmd = CommandRegistrar::getInstance()
                    .getOrCreateCommand("levilamina", "LeviLamina's main command"_tr(), CommandPermissionLevel::Host);
    ll::service::getCommandRegistry()->registerAlias("levilamina", "ll");

    cmd.overload<LeviCommand3>()
        .text("load")
        .required("plugin")
        .execute<[](CommandOrigin const&, CommandOutput& output, LeviCommand3 const& param) {
            if (ll::plugin::PluginManagerRegistry::getInstance().hasPlugin(param.plugin)) {
                output.error("Plugin already {0} loaded"_tr(param.plugin));
                return;
            }
            if (ll::plugin::PluginRegistrar::getInstance().loadPlugin(param.plugin)) {
                output.success("Load plugin {0} successfully"_tr(param.plugin));
            } else {
                output.error("Failed to load plugin {0}"_tr(param.plugin));
            }
        }>();
    cmd.overload<LeviCommand>()
        .required("operation")
        .required("plugin")
        .execute<[](CommandOrigin const&, CommandOutput& output, LeviCommand const& param) {
            if (!ll::plugin::PluginManagerRegistry::getInstance().hasPlugin(param.plugin)) {
                output.error("Plugin {0} not found"_tr(param.plugin));
                return;
            }
            switch (param.operation) {
            case LeviCommandOperation::unload:
                if (ll::plugin::PluginRegistrar::getInstance().unloadPlugin(param.plugin)) {
                    output.success("Unload plugin {0} successfully"_tr(param.plugin));
                } else {
                    output.error("Failed to unload plugin {0}"_tr(param.plugin));
                }
                break;
            case LeviCommandOperation::reload:
                if (ll::plugin::PluginRegistrar::getInstance().unloadPlugin(param.plugin)
                    && ll::plugin::PluginRegistrar::getInstance().loadPlugin(param.plugin)) {
                    output.success("Reload plugin {0} successfully"_tr(param.plugin));
                } else {
                    output.error("Failed to reload plugin {0}"_tr(param.plugin));
                }
                break;
            case LeviCommandOperation::reactivate:
                if (ll::plugin::PluginRegistrar::getInstance().disablePlugin(param.plugin)
                    && ll::plugin::PluginRegistrar::getInstance().enablePlugin(param.plugin)) {
                    output.success("Reactivate plugin {0} successfully"_tr(param.plugin));
                } else {
                    output.error("Failed to reactivate plugin {0}"_tr(param.plugin));
                }
                break;
            default:
                std::unreachable();
            }
        }>();
    cmd.overload<LeviCommand2>()
        .required("operation")
        .required("plugin")
        .execute<[](CommandOrigin const&, CommandOutput& output, LeviCommand2 const& param) {
            if (!ll::plugin::PluginManagerRegistry::getInstance().hasPlugin(param.plugin)) {
                output.error("Plugin {0} not found"_tr(param.plugin));
                return;
            }
            switch (param.operation) {
            case LeviCommandOperation2::enable:
                if (ll::plugin::PluginRegistrar::getInstance().enablePlugin(param.plugin)) {
                    output.success("Enable plugin {0} successfully"_tr(param.plugin));
                } else {
                    output.error("Failed to enable plugin {0}"_tr(param.plugin));
                }
                break;
            case LeviCommandOperation2::disable:
                if (ll::plugin::PluginRegistrar::getInstance().disablePlugin(param.plugin)) {
                    output.success("Disable plugin {0} successfully"_tr(param.plugin));
                } else {
                    output.error("Failed to disable plugin {0}"_tr(param.plugin));
                }
                break;
            case LeviCommandOperation2::show: {
                auto plugin = ll::plugin::PluginManagerRegistry::getInstance().getPlugin(param.plugin);
                if (!plugin) {
                    output.error("Plugin {0} not found"_tr(param.plugin));
                    return;
                }
                plugin::Manifest const& man = plugin->getManifest();
                output.success("Name: {0}"_tr(man.name));
                if (man.author) {
                    output.success("Author: {0}"_tr(*man.author));
                }
                if (man.description) {
                    output.success("Description: {0}"_tr(*man.description));
                }
                output.success("Type: {0}"_tr(man.type));
                if (man.version) {
                    output.success("Version: {0}"_tr(man.version->to_string()));
                }
                output.success("Entry: {0}"_tr(man.entry));
                break;
            }
            default:
                std::unreachable();
            }
        }>();
    cmd.overload().text("list").execute<[](CommandOrigin const&, CommandOutput& output) {
        size_t      amount = 0;
        std::string plugins;
        ll::plugin::PluginManagerRegistry::getInstance().forEachPluginWithType(
            [&amount, &plugins](std::string_view, std::string_view name, plugin::Plugin&) {
                ++amount;
                plugins = plugins.append(name).append(", ");
                return true;
            }
        );
        if (!plugins.empty()) {
            plugins.resize(plugins.size() - 2);
        }
        output.success("There are {0} plugins: {1}"_tr(amount, plugins));
    }>();
}
} // namespace ll::command
