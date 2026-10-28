// SevenGet - shared state for command implementations.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "cli/args.h"
#include "core/config.h"
#include "core/database.h"
#include "core/repository.h"
#include "core/resolver.h"
#include "platform/winutil.h"
#include "util/json.h"

namespace sg {

struct CommandContext {
    ParsedArgs args;
    Config config;
    Database db;
    std::unique_ptr<RepositoryManager> repos;
    std::unique_ptr<InstanceLock> lock;
    Json out = Json::Object();          // JSON result document (--json)
    std::vector<std::string> warnings;  // collected, printed or emitted in JSON

    void OpenDatabase();
    // Takes the per-user operation lock; throws kExitBusy if held.
    void AcquireLock();
    void LoadRepositories(bool allowExpired);
    ResolveOptions MakeResolveOptions() const;
    void Warn(const std::string& w);
};

std::string DatabasePath();

// Command entry points (return exit codes; throw sg::Error on failure).
int CmdRepo(CommandContext& c);
int CmdConfig(CommandContext& c);
int CmdDoctor(CommandContext& c);
int CmdClean(CommandContext& c);
int CmdUpdate(CommandContext& c);

}  // namespace sg
