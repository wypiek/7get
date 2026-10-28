#include "core/resolver.h"

#include <algorithm>
#include <set>

#include "util/error.h"
#include "util/strings.h"
#include "util/version.h"

namespace sg {

PlatformInfo PlatformInfo::Current() {
    const OsInfo& os = GetOsInfo();
    PlatformInfo p;
    p.winMajor = os.major;
    p.winMinor = os.minor;
    p.winBuild = os.build;
    p.nativeArch = os.nativeArch;
    return p;
}

std::vector<Arch> AcceptableArchs(const PlatformInfo& p, Arch requested) {
    std::vector<Arch> runnable;
    switch (p.nativeArch) {
        case Arch::X64: runnable = {Arch::X64, Arch::X86}; break;
        case Arch::X86: runnable = {Arch::X86}; break;
        case Arch::Arm64:
            // x64 emulation exists only on Windows 11 (build 22000+); x86 emulation on all.
            if (p.winMajor >= 10 && p.winBuild >= 22000) runnable = {Arch::X64, Arch::X86};
            else runnable = {Arch::X86};
            break;
        default: runnable = {Arch::X86}; break;
    }
    if (requested == Arch::Unknown) return runnable;
    if (std::find(runnable.begin(), runnable.end(), requested) != runnable.end()) return {requested};
    return {};
}

bool IsInstallerCompatible(const Installer& in, const PlatformInfo& p, std::string& reason) {
    if (CompareWindowsVersion(p.winMajor, p.winMinor, in.minWinMajor, in.minWinMinor) < 0) {
        reason = "requires Windows NT " + std::to_string(in.minWinMajor) + "." + std::to_string(in.minWinMinor) +
                 " or later";
        return false;
    }
    if (in.hasMaxWin && CompareWindowsVersion(p.winMajor, p.winMinor, in.maxWinMajor, in.maxWinMinor) > 0) {
        reason = "supports Windows NT up to " + std::to_string(in.maxWinMajor) + "." + std::to_string(in.maxWinMinor);
        return false;
    }
    return true;
}

namespace {

std::vector<const Release*> SortedReleases(const Package& pkg) {
    std::vector<const Release*> rels;
    for (const auto& r : pkg.releases) rels.push_back(&r);
    std::sort(rels.begin(), rels.end(),
              [](const Release* a, const Release* b) { return CompareVersions(a->version, b->version) > 0; });
    return rels;
}

// Picks the best installer of a release, or explains why none fits.
const Installer* PickInstaller(const Release& r, const PlatformInfo& p, const ResolveOptions& o, Scope& scope,
                               std::string& why) {
    std::vector<Arch> archs = AcceptableArchs(p, o.arch);
    if (archs.empty()) {
        why = std::string("architecture ") + ArchName(o.arch) + " cannot run on this " + ArchName(p.nativeArch) + " system";
        return nullptr;
    }
    std::string osReason, scopeReason, archReason = "no installer for " + std::string(ArchName(archs.front()));
    for (Arch a : archs) {
        for (InstallerType t : o.typePreference) {
            for (const auto& in : r.installers) {
                if (in.arch != a || in.type != t) continue;
                std::string reason;
                if (!IsInstallerCompatible(in, p, reason)) { osReason = reason; continue; }
                if (o.scopeSpecified) {
                    if (!in.SupportsScope(o.scope)) {
                        scopeReason = std::string("no installer supports ") + ScopeName(o.scope) + " scope";
                        continue;
                    }
                    scope = o.scope;
                } else {
                    scope = in.SupportsScope(Scope::User) ? Scope::User : Scope::Machine;
                }
                return &in;
            }
        }
    }
    why = !osReason.empty() ? osReason : !scopeReason.empty() ? scopeReason : archReason;
    return nullptr;
}

}  // namespace

ResolveResult ResolvePackage(const Package& pkg, const PlatformInfo& p, const ResolveOptions& o) {
    ResolveResult res;
    if (!o.version.empty()) {
        const Release* rel = nullptr;
        for (const auto& r : pkg.releases)
            if (CompareVersions(r.version, o.version) == 0 && EqualsIgnoreCase(r.version, o.version)) rel = &r;
        if (!rel)
            for (const auto& r : pkg.releases)
                if (CompareVersions(r.version, o.version) == 0) rel = &r;
        if (!rel) {
            res.errorCode = kExitNotFound;
            std::vector<std::string> vs;
            for (const auto* r : SortedReleases(pkg)) vs.push_back(r->version);
            res.error = "version " + o.version + " of " + pkg.id + " is not in the repository (available: " +
                        Join(vs, ", ") + ")";
            return res;
        }
        std::string why;
        Scope scope;
        const Installer* in = PickInstaller(*rel, p, o, scope, why);
        if (!in) {
            res.errorCode = kExitIncompatible;
            res.error = pkg.id + " " + rel->version + " is not compatible with this system: " + why;
            return res;
        }
        res.ok = true;
        res.candidate = {&pkg, rel, in, scope};
        return res;
    }
    for (const Release* rel : SortedReleases(pkg)) {
        std::string why;
        Scope scope;
        const Installer* in = PickInstaller(*rel, p, o, scope, why);
        if (in) {
            res.ok = true;
            res.candidate = {&pkg, rel, in, scope};
            return res;
        }
        res.skipped.push_back(rel->version + ": " + why);
    }
    res.errorCode = kExitIncompatible;
    res.error = "no release of " + pkg.id + " is marked compatible with Windows NT " + std::to_string(p.winMajor) + "." +
                std::to_string(p.winMinor) + " " + ArchName(p.nativeArch) + " (" + Join(res.skipped, "; ") + ")";
    return res;
}

const Release* NewestCompatibleRelease(const Package& pkg, const PlatformInfo& p, const ResolveOptions& o) {
    ResolveOptions copy = o;
    copy.version.clear();
    ResolveResult r = ResolvePackage(pkg, p, copy);
    return r.ok ? r.candidate.release : nullptr;
}

DependencyPlan ResolveDependencies(const Candidate& root, const PlatformInfo& p, const ResolveOptions& o,
                                   const PackageLookup& lookup, const InstalledLookup& installed) {
    DependencyPlan plan;
    std::set<std::string> done;      // lower-cased ids already planned or satisfied
    std::vector<std::string> stack;  // for cycle detection
    ResolveOptions depOpts;
    depOpts.arch = Arch::Unknown;    // dependencies use the best native arch
    depOpts.typePreference = o.typePreference;
    depOpts.scopeSpecified = o.scopeSpecified;
    depOpts.scope = o.scope;

    std::function<bool(const Candidate&, bool)> visit = [&](const Candidate& c, bool isDep) -> bool {
        std::string key = ToLowerAscii(c.package->id);
        if (std::find(stack.begin(), stack.end(), key) != stack.end()) {
            plan.errorCode = kExitError;
            plan.error = "dependency cycle detected: " + Join(stack, " -> ") + " -> " + key;
            return false;
        }
        if (done.count(key)) return true;
        if (stack.size() > 32) {
            plan.errorCode = kExitError;
            plan.error = "dependency chain too deep";
            return false;
        }
        stack.push_back(key);
        for (const auto& dep : c.release->dependencies) {
            std::string dkey = ToLowerAscii(dep.id);
            if (done.count(dkey)) continue;
            std::string have = installed(dep.id);
            if (!have.empty() && (dep.minVersion.empty() || CompareVersions(have, dep.minVersion) >= 0)) {
                done.insert(dkey);
                continue;
            }
            const Package* dp = lookup(dep.id);
            if (!dp) {
                plan.errorCode = kExitNotFound;
                plan.error = c.package->id + " requires " + dep.id + ", which is not available in any enabled repository";
                return false;
            }
            ResolveResult rr = ResolvePackage(*dp, p, depOpts);
            if (!rr.ok) {
                plan.errorCode = rr.errorCode;
                plan.error = "dependency " + dep.id + ": " + rr.error;
                return false;
            }
            if (!dep.minVersion.empty() && CompareVersions(rr.candidate.release->version, dep.minVersion) < 0) {
                plan.errorCode = kExitIncompatible;
                plan.error = c.package->id + " requires " + dep.id + " >= " + dep.minVersion +
                             " but the newest compatible release is " + rr.candidate.release->version;
                return false;
            }
            if (!visit(rr.candidate, true)) return false;
        }
        stack.pop_back();
        done.insert(key);
        plan.steps.push_back({c, isDep});
        return true;
    };
    plan.ok = visit(root, false);
    return plan;
}

}  // namespace sg
