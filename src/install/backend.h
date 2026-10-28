// SevenGet - installer backend interface.
//
// Each installer type has its own backend with its own install, verification
// and uninstall logic:
//   ExeBackend  - vendor setup.exe with documented silent switches; ownership
//                 is the exact Uninstall registry key the manifest names.
//   MsiBackend  - Windows Installer via msiexec; ownership is the ProductCode
//                 read from the verified package.
//   ZipBackend  - portable archives extracted by SevenGet; ownership is the
//                 recorded list of extracted files inside SevenGet's app root.
//
// The `uninstall` JSON stored in the database is produced and consumed only by
// the backend that created it.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "core/database.h"
#include "core/manifest.h"
#include "platform/authenticode.h"
#include "util/json.h"

namespace sg {

struct InstallContext {
    const Package* package = nullptr;
    const Release* release = nullptr;
    const Installer* installer = nullptr;
    Scope scope = Scope::User;
    std::string packageFile;       // verified download
    std::string tempDir;           // per-transaction scratch directory (logs)
    const InstalledRecord* previous = nullptr;  // set for upgrades
    bool requireAuthenticode = false;           // config security.requireAuthenticode
    RevocationMode revocation = RevocationMode::Soft;
    std::function<void(const std::string&)> status;  // progress messages
};

struct BackendResult {
    enum class Status { Success, RebootRequired, Failed, Cancelled, ElevationDenied, Busy, IntegrityFailed };
    Status status = Status::Failed;
    std::string message;
    uint32_t exitCode = 0;
    std::string installLocation;
    Json uninstall = Json::Object();
    std::vector<std::string> files;
    bool alreadyGone = false;  // uninstall: target had already been removed outside SevenGet
    bool Ok() const { return status == Status::Success || status == Status::RebootRequired; }
};

class InstallerBackend {
public:
    virtual ~InstallerBackend() = default;
    virtual InstallerType type() const = 0;
    virtual BackendResult Install(const InstallContext& ctx) = 0;
    virtual BackendResult Uninstall(const InstalledRecord& rec) = 0;
    // Cheap check whether the recorded installation still exists.
    virtual bool IsPresent(const InstalledRecord& rec) = 0;
};

std::unique_ptr<InstallerBackend> CreateBackend(InstallerType t);
bool InstallerTypeFromName(const std::string& name, InstallerType& out);

// Maps an installer process exit code using the manifest's lists.
BackendResult::Status ClassifyExitCode(uint32_t code, const std::vector<int64_t>& success,
                                       const std::vector<int64_t>& reboot);
std::string DescribeInstallerExitCode(uint32_t code);

// Uninstall command executables that are never run even if a registry
// UninstallString points at them (script hosts / generic launchers).
bool IsForbiddenUninstallHost(const std::string& exePath);

}  // namespace sg
