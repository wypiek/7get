// SevenGet - version, compatibility and dependency resolution.
//
// Selection rule: among all releases of a package, choose the newest version
// that has at least one installer explicitly declared compatible with the
// running Windows version (minWindows <= os <= maxWindows) and architecture.
// The newest upstream release is never chosen merely because it is newest.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "core/manifest.h"

namespace sg {

struct PlatformInfo {
    int winMajor = 6, winMinor = 1, winBuild = 7601;
    Arch nativeArch = Arch::X64;
    static PlatformInfo Current();
};

struct ResolveOptions {
    std::string version;                 // exact version requested, empty = newest compatible
    Arch arch = Arch::Unknown;           // Unknown = auto
    bool scopeSpecified = false;
    Scope scope = Scope::User;
    std::vector<InstallerType> typePreference{InstallerType::Msi, InstallerType::Exe, InstallerType::Zip};
};

struct Candidate {
    const Package* package = nullptr;
    const Release* release = nullptr;
    const Installer* installer = nullptr;
    Scope scope = Scope::Machine;
};

struct ResolveResult {
    bool ok = false;
    Candidate candidate;
    int errorCode = 0;            // ExitCode on failure
    std::string error;            // explanation, includes why newer releases were skipped
    std::vector<std::string> skipped;  // "26.05: requires Windows 10.0 or later"
};

// Architectures this system can execute, in preference order.
std::vector<Arch> AcceptableArchs(const PlatformInfo& p, Arch requested);

// Checks a single installer against platform; returns false with reason.
bool IsInstallerCompatible(const Installer& in, const PlatformInfo& p, std::string& reason);

ResolveResult ResolvePackage(const Package& pkg, const PlatformInfo& p, const ResolveOptions& o);

// Newest release that is compatible (for list/outdated/search display).
const Release* NewestCompatibleRelease(const Package& pkg, const PlatformInfo& p, const ResolveOptions& o);

struct PlanStep {
    Candidate candidate;
    bool dependency = false;  // pulled in by another package
};

using PackageLookup = std::function<const Package*(const std::string& id)>;
// Returns installed version or empty string when not installed.
using InstalledLookup = std::function<std::string(const std::string& id)>;

struct DependencyPlan {
    bool ok = false;
    int errorCode = 0;
    std::string error;
    std::vector<PlanStep> steps;  // dependencies first, root last
};

DependencyPlan ResolveDependencies(const Candidate& root, const PlatformInfo& p, const ResolveOptions& o,
                                   const PackageLookup& lookup, const InstalledLookup& installed);

}  // namespace sg
