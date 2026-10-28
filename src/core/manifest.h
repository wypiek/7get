// SevenGet - package manifest model and validation.
//
// See docs/manifest-schema.md for the authoritative schema. Every field that
// reaches the file system, the registry or a command line is validated here so
// that the installer backends can rely on well-formed input.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "platform/winutil.h"
#include "util/json.h"

namespace sg {

enum class InstallerType { Exe, Msi, Zip };
const char* InstallerTypeName(InstallerType t);

enum class Scope { User, Machine };
const char* ScopeName(Scope s);

struct UninstallSpec {
    // "registry" (exe), "msi" (msi), "files" (zip)
    std::string strategy;
    std::string registryKey;               // exe: exact subkey under ...\CurrentVersion\Uninstall
    std::vector<std::string> quietArgs;    // exe: args appended to UninstallString when no QuietUninstallString
};

struct SignatureSpec {
    bool required = false;
    std::string subject;              // expected signer simple display name (exact, case-insensitive)
    std::vector<std::string> files;   // zip: archive entries whose Authenticode signature is verified
};

struct Installer {
    Arch arch = Arch::Unknown;
    InstallerType type = InstallerType::Exe;
    std::string url;
    std::string sha256;  // lowercase hex
    uint64_t size = 0;   // bytes, 0 = unknown
    int minWinMajor = 6, minWinMinor = 1;
    bool hasMaxWin = false;
    int maxWinMajor = 0, maxWinMinor = 0;
    std::vector<Scope> scopes;
    std::vector<std::string> silentArgs;   // exe: literal tokens; msi: PROPERTY=value tokens
    std::vector<int64_t> successExitCodes;
    std::vector<int64_t> rebootExitCodes;
    std::string productCode;               // msi: optional expected {GUID}
    std::string upgradeBehavior;           // "install-over" | "uninstall-first"
    UninstallSpec uninstall;
    SignatureSpec signature;
    std::string notes;                     // compatibility notes / sources
    bool SupportsScope(Scope s) const;
};

struct Dependency {
    std::string id;
    std::string minVersion;  // optional
};

struct Release {
    std::string version;
    std::string releaseDate;  // YYYY-MM-DD, informational
    std::vector<Dependency> dependencies;
    std::vector<Installer> installers;
};

struct Package {
    std::string id;
    std::string name;
    std::string publisher;
    std::string description;
    std::string license;
    std::string homepage;
    std::vector<std::string> tags;
    std::vector<Release> releases;
    std::string repository;  // set by the repository loader
};

// Identifier rules shared by package ids and repository names.
bool IsValidPackageId(const std::string& id);
bool IsValidRepoName(const std::string& name);
bool IsValidSha256Hex(const std::string& s);
bool IsValidGuid(const std::string& s);  // {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// Rejects control characters, quotes and NUL; length-limited.
bool IsSafeArgument(const std::string& s);

// Parses and validates one manifest object. On failure errors[] lists every problem found.
bool ParsePackage(const Json& j, Package& out, std::vector<std::string>& errors);

// Back to JSON (for --json output and the repository tool).
Json PackageToJson(const Package& p);
Json InstallerToJson(const Installer& i);

}  // namespace sg
