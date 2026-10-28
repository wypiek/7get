// SevenGet - installation engine.
//
// Workflow for install/upgrade (each step is visible in the console output):
//   1. resolve package and version        6. download over HTTPS (resumable)
//   2. check Windows version / arch       7. verify SHA-256 (file locked against writes)
//   3. resolve dependencies               8. verify Authenticode where required
//   4. metadata already verified          9. check permissions / elevation
//      (signature, rollback, expiry)     10. confirm (unless --yes)
//   5. show plan; stop here on --dry-run 11. run the type-specific backend
//                                        12. verify the result, record in DB
//                                        13. clean up temporary files
#pragma once

#include <string>
#include <vector>

#include "core/config.h"
#include "core/database.h"
#include "core/repository.h"
#include "core/resolver.h"
#include "util/json.h"

namespace sg {

struct EngineOptions {
    bool yes = false;
    bool dryRun = false;
    bool force = false;
    ResolveOptions resolve;
};

class Engine {
public:
    Engine(Database& db, RepositoryManager& repos, const Config& cfg);

    int Install(const std::string& id, const EngineOptions& o, Json& out);
    int Upgrade(const std::vector<std::string>& ids, bool all, const EngineOptions& o, Json& out);
    int Uninstall(const std::string& id, const EngineOptions& o, Json& out);
    int Download(const std::string& id, const EngineOptions& o, const std::string& outDir, Json& out);

    // Downloads (or reuses from cache) and verifies a package file. Throws sg::Error.
    std::string FetchVerified(const Candidate& c, Json& info);

private:
    struct Outcome {
        bool ok = false;
        bool reboot = false;
        int code = 0;
        std::string message;
    };
    Outcome ExecuteInstall(const Candidate& c, bool dependency, const InstalledRecord* previous, const std::string& action);
    bool ConfirmPlan(const std::string& question, const EngineOptions& o);
    void CheckPermissions(const Candidate& c);
    void WarnWindows7();
    std::string InstalledVersion(const std::string& id);
    void Snapshot();

    Database& db_;
    RepositoryManager& repos_;
    const Config& cfg_;
    PlatformInfo platform_;
};

Json CandidateToJson(const Candidate& c);

}  // namespace sg
