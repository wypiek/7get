// SevenGet - error type and process exit codes.
#pragma once

#include <stdexcept>
#include <string>

namespace sg {

// Process exit codes. These values are part of the documented CLI contract
// (docs/commands.md) and must not be renumbered.
enum ExitCode : int {
    kExitOk = 0,
    kExitError = 1,            // unexpected/general failure
    kExitUsage = 2,            // invalid arguments
    kExitNotFound = 3,         // package / repository / key not found
    kExitNetwork = 4,          // download or TLS failure
    kExitIntegrity = 5,        // SHA-256 mismatch, Authenticode failure, tampered file
    kExitTrust = 6,            // repository signature, rollback, expiry, key problems
    kExitInstallerFailed = 7,  // installer returned a failure code / post-install check failed
    kExitCancelled = 8,        // user declined or pressed Ctrl+C
    kExitPermission = 9,       // elevation refused / access denied
    kExitDatabase = 10,        // local database error or corruption
    kExitIncompatible = 11,    // no release compatible with this Windows version/arch
    kExitRebootRequired = 12,  // operation succeeded, restart required to complete
    kExitBusy = 13,            // another SevenGet instance or Windows Installer is busy
};

class Error : public std::runtime_error {
public:
    Error(int code, const std::string& message, std::string hint = {})
        : std::runtime_error(message), code_(code), hint_(std::move(hint)) {}
    int code() const { return code_; }
    const std::string& hint() const { return hint_; }

private:
    int code_;
    std::string hint_;
};

const char* ExitCodeName(int code);

}  // namespace sg
