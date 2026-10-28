#include "install/engine.h"

#include <windows.h>

#include <algorithm>

#include "install/backend.h"
#include "platform/authenticode.h"
#include "platform/console.h"
#include "platform/crypto.h"
#include "platform/http.h"
#include "platform/winutil.h"
#include "util/error.h"
#include "util/log.h"
#include "util/strings.h"
#include "util/version.h"

namespace sg {

namespace {

std::string ShortHex(const std::string& h) { return h.substr(0, 12); }

std::string ProgressBar(double fraction, int width) {
    if (fraction < 0) fraction = 0;
    if (fraction > 1) fraction = 1;
    int filled = static_cast<int>(fraction * width + 0.5);
    return "[" + std::string(static_cast<size_t>(filled), '#') + std::string(static_cast<size_t>(width - filled), '-') + "]";
}

// Holds a read handle that denies writers and deleters so the verified file
// cannot be swapped between verification and execution.
class FileLock {
public:
    explicit FileLock(const std::string& path) {
        h_ = CreateFileW(Widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    ~FileLock() {
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
    }
    bool ok() const { return h_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE h_;
};

std::string ExtensionFor(InstallerType t) { return std::string(".") + InstallerTypeName(t); }

int ExitFromStatus(BackendResult::Status s) {
    switch (s) {
        case BackendResult::Status::Success: return kExitOk;
        case BackendResult::Status::RebootRequired: return kExitRebootRequired;
        case BackendResult::Status::Cancelled: return kExitCancelled;
        case BackendResult::Status::ElevationDenied: return kExitPermission;
        case BackendResult::Status::Busy: return kExitBusy;
        case BackendResult::Status::IntegrityFailed: return kExitIntegrity;
        default: return kExitInstallerFailed;
    }
}

const char* TxStateFor(BackendResult::Status s) {
    switch (s) {
        case BackendResult::Status::Success: return "succeeded";
        case BackendResult::Status::RebootRequired: return "reboot-required";
        case BackendResult::Status::Cancelled: return "cancelled";
        default: return "failed";
    }
}

}  // namespace

Json CandidateToJson(const Candidate& c) {
    Json j = Json::Object();
    j.Set("id", c.package->id);
    j.Set("name", c.package->name);
    j.Set("version", c.release->version);
    j.Set("arch", ArchName(c.installer->arch));
    j.Set("installerType", InstallerTypeName(c.installer->type));
    j.Set("scope", ScopeName(c.scope));
    j.Set("repository", c.package->repository);
    j.Set("url", c.installer->url);
    j.Set("sha256", c.installer->sha256);
    if (c.installer->size) j.Set("size", static_cast<int64_t>(c.installer->size));
    return j;
}

Engine::Engine(Database& db, RepositoryManager& repos, const Config& cfg)
    : db_(db), repos_(repos), cfg_(cfg), platform_(PlatformInfo::Current()) {}

void Engine::WarnWindows7() {
    if (GetOsInfo().IsWindows7() && cfg_.GetBool("warnings.windows7"))
        Console::Warn("Windows 7 no longer receives security updates from Microsoft. SevenGet verifies what it "
                      "installs, but it cannot make Windows 7 secure. (config: warnings.windows7)");
}

std::string Engine::InstalledVersion(const std::string& id) {
    auto recs = db_.FindInstalled(id);
    return recs.empty() ? std::string() : recs.front().version;
}

void Engine::Snapshot() { db_.WriteSnapshotFile(JoinPath(GetAppPaths().dataDir, "installed-snapshot.json")); }

bool Engine::ConfirmPlan(const std::string& question, const EngineOptions& o) {
    if (o.yes) return true;
    if (Console::Options().json)
        throw Error(kExitUsage, "--json requires --yes for operations that change the system");
    if (!Console::StdinIsConsole())
        throw Error(kExitUsage, "confirmation required but input is not interactive; re-run with --yes");
    return Console::Confirm(question);
}

void Engine::CheckPermissions(const Candidate& c) {
    Console::Step("Checking installation permissions");
    bool elevated = IsProcessElevated();
    if (c.scope == Scope::User) {
        Console::StepResult("OK (per-user installation, no administrator rights needed)", Color::Green);
        return;
    }
    if (c.installer->type == InstallerType::Zip && !elevated) {
        Console::StepResult("FAILED", Color::Red);
        throw Error(kExitPermission, "machine-wide portable installation needs an elevated Command Prompt",
                    "use --user, or start cmd.exe with 'Run as administrator'");
    }
    Console::StepResult(elevated ? "OK (running as administrator)"
                                 : "administrator rights required - Windows will show a UAC prompt",
                        elevated ? Color::Green : Color::Yellow);
}

std::string Engine::FetchVerified(const Candidate& c, Json& info) {
    const Installer& in = *c.installer;
    std::string dir = JoinPath(JoinPath(JoinPath(GetAppPaths().cacheDir, "downloads"), c.package->id), c.release->version);
    if (!CreateDirectories(dir)) throw Error(kExitError, "cannot create cache directory " + dir);
    std::string file = JoinPath(dir, std::string(ArchName(in.arch)) + "-" + ShortHex(in.sha256) + ExtensionFor(in.type));
    info.Set("file", file);

    bool cached = false;
    if (FileExists(file)) {
        std::string hex, err;
        if (Sha256File(file, hex, err) && DigestEquals(hex, in.sha256)) cached = true;
        else DeleteFileUtf8(file);
    }
    if (cached) {
        Console::Info("Using verified cached download " + FileName(file));
    } else {
        std::string name = FileName(in.url.substr(0, in.url.find('?')));
        Log::Info("download " + in.url);
        HttpError herr;
        uint64_t maxBytes = in.size ? in.size : (4ull << 30);
        bool console = Console::StderrIsConsole();
        if (!console) Console::Info("Downloading " + in.url);
        DWORD start = GetTickCount();
        bool ok = HttpDownloadFile(in.url, file, maxBytes, [&](uint64_t done, uint64_t total, double rate) {
            if (total == 0) total = in.size;
            std::string line = "Downloading " + name + " ";
            if (total) {
                double f = static_cast<double>(done) / static_cast<double>(total);
                char pct[8];
                std::snprintf(pct, sizeof pct, "%3d%%", static_cast<int>(f * 100));
                line += ProgressBar(f, 20) + " " + pct + "  " + FormatBytes(done) + " / " + FormatBytes(total);
                if (rate > 0) {
                    line += "  " + FormatRate(rate);
                    if (done < total) line += "  ETA " + FormatDuration(static_cast<double>(total - done) / rate);
                }
            } else {
                line += FormatBytes(done) + (rate > 0 ? "  " + FormatRate(rate) : "");
            }
            Console::Progress(line);
            return !CancelRequested();
        }, herr);
        Console::EndProgress();
        if (!ok) {
            int code = herr.kind == HttpError::Kind::Cancelled ? kExitCancelled
                       : herr.kind == HttpError::Kind::TooLarge ? kExitIntegrity
                       : herr.kind == HttpError::Kind::Io      ? kExitError
                                                               : kExitNetwork;
            Log::Error("download failed: " + herr.message);
            throw Error(code, "download failed: " + herr.message,
                        code == kExitCancelled ? "the partial download is kept and will resume next time" : herr.hint);
        }
        double secs = (GetTickCount() - start) / 1000.0;
        if (!console)
            Console::Info("Downloaded " + FormatBytes(FileSize(file)) + " in " + FormatDuration(secs));
    }

    // Lock against modification, then verify.
    FileLock lock(file);
    Console::Step("Verifying SHA-256");
    std::string hex, err;
    if (!lock.ok() || !Sha256File(file, hex, err)) {
        Console::StepResult("FAILED", Color::Red);
        throw Error(kExitIntegrity, "could not hash downloaded file: " + err);
    }
    if (!DigestEquals(hex, in.sha256)) {
        Console::StepResult("MISMATCH", Color::Red);
        DeleteFileUtf8(file);
        Log::Error("sha256 mismatch for " + in.url + ": got " + hex);
        throw Error(kExitIntegrity,
                    "SHA-256 mismatch: expected " + in.sha256 + ", got " + hex + ". The file was deleted.",
                    "the download was corrupted or tampered with; nothing was installed");
    }
    if (in.size && FileSize(file) != in.size) {
        Console::StepResult("SIZE MISMATCH", Color::Red);
        throw Error(kExitIntegrity, "downloaded size does not match the manifest");
    }
    Console::StepResult("OK", Color::Green);
    info.Set("sha256Verified", true);

    // Authenticode (exe and msi; zip contents are checked by the zip backend).
    if (in.type != InstallerType::Zip) {
        bool required = in.signature.required || cfg_.GetBool("security.requireAuthenticode");
        RevocationMode mode = cfg_.Get("security.revocation") == "hard" ? RevocationMode::Hard : RevocationMode::Soft;
        Console::Step("Verifying Authenticode signature");
        AuthenticodeResult ar = VerifyAuthenticode(file, mode);
        bool subjectOk = in.signature.subject.empty() || EqualsIgnoreCase(ar.signerSubject, in.signature.subject);
        Json a = Json::Object();
        a.Set("required", required);
        a.Set("signer", ar.signerSubject);
        a.Set("result", ar.message);
        if (ar.status == AuthenticodeResult::Status::Valid && subjectOk) {
            Console::StepResult("OK (signed by " + ar.signerSubject + ")" +
                                    (ar.revocationUnchecked ? ", revocation not checked" : ""),
                                Color::Green);
            a.Set("valid", true);
        } else if (required) {
            Console::StepResult("FAILED", Color::Red);
            throw Error(kExitIntegrity,
                        "Authenticode verification failed: " +
                            (subjectOk ? ar.message
                                       : "signed by '" + ar.signerSubject + "', expected '" + in.signature.subject + "'"),
                        GetOsInfo().IsWindows7()
                            ? "Windows 7 needs SHA-2 code signing support (KB4474419) and current root certificates"
                            : "");
        } else if (ar.status == AuthenticodeResult::Status::NotSigned) {
            Console::StepResult("not signed by publisher (integrity guaranteed by SHA-256 from signed metadata)",
                                Color::Yellow);
            a.Set("valid", false);
        } else {
            Console::StepResult("could not verify: " + ar.message + " (not required for this package)", Color::Yellow);
            a.Set("valid", false);
        }
        info.Set("authenticode", a);
    }
    return file;
}

Engine::Outcome Engine::ExecuteInstall(const Candidate& c, bool dependency, const InstalledRecord* previous,
                                       const std::string& action) {
    Outcome res;
    TransactionRecord tr;
    tr.action = action;
    tr.packageId = c.package->id;
    tr.fromVersion = previous ? previous->version : "";
    tr.toVersion = c.release->version;
    tr.scope = ScopeName(c.scope);
    int64_t txId = db_.StartTransaction(tr);
    Log::Info(action + " " + c.package->id + " " + c.release->version + " (" + InstallerTypeName(c.installer->type) +
              ", " + ScopeName(c.scope) + ") started");
    std::string tempDir = JoinPath(GetAppPaths().tempDir, "tx-" + std::to_string(txId));
    CreateDirectories(tempDir);
    auto finish = [&](const char* state, const std::string& msg) {
        db_.FinishTransaction(txId, state, msg);
        Log::Info(action + " " + c.package->id + " " + state + (msg.empty() ? "" : ": " + msg));
    };
    try {
        Json info = Json::Object();
        std::string file = FetchVerified(c, info);
        FileLock lock(file);
        if (!lock.ok()) throw Error(kExitIntegrity, "verified file could not be locked for installation");
        {
            // Re-hash under the lock that is held until the installer exits, closing
            // the window between verification and execution.
            std::string hex, err;
            if (!Sha256File(file, hex, err) || !DigestEquals(hex, c.installer->sha256))
                throw Error(kExitIntegrity, "package file changed after verification; aborting");
        }

        // Upgrades that cannot be applied in place remove the old version first.
        auto backend = CreateBackend(c.installer->type);
        const InstalledRecord* prevForBackend = previous;
        InstalledRecord prevCopy;
        if (previous) {
            InstallerType oldType;
            bool typeChanged = !InstallerTypeFromName(previous->installerType, oldType) || oldType != c.installer->type;
            if ((typeChanged || c.installer->upgradeBehavior == "uninstall-first") && c.installer->type != InstallerType::Zip) {
                Console::Info("Removing " + previous->packageId + " " + previous->version + " before installing " +
                              c.release->version + "...");
                auto oldBackend = CreateBackend(typeChanged ? oldType : c.installer->type);
                BackendResult ur = oldBackend ? oldBackend->Uninstall(*previous) : BackendResult{};
                if (!ur.Ok()) {
                    res.code = ExitFromStatus(ur.status);
                    res.message = "could not remove the previous version: " + ur.message;
                    finish("failed", res.message);
                    RemoveTree(tempDir);
                    return res;
                }
                db_.RemoveInstalled(previous->packageId, previous->scope);
                prevCopy = *previous;
                prevForBackend = nullptr;
            }
        }

        InstallContext ctx;
        ctx.package = c.package;
        ctx.release = c.release;
        ctx.installer = c.installer;
        ctx.scope = c.scope;
        ctx.packageFile = file;
        ctx.tempDir = tempDir;
        ctx.previous = prevForBackend;
        ctx.requireAuthenticode = cfg_.GetBool("security.requireAuthenticode");
        ctx.revocation = cfg_.Get("security.revocation") == "hard" ? RevocationMode::Hard : RevocationMode::Soft;
        ctx.status = [](const std::string& s) { Console::Info(s); };
        BackendResult br = backend->Install(ctx);
        if (!br.Ok()) {
            res.code = ExitFromStatus(br.status);
            res.message = br.message;
            if (!prevCopy.packageId.empty())
                res.message += " (the previous version " + prevCopy.version + " had already been removed)";
            finish(TxStateFor(br.status), res.message);
            return res;  // tempDir kept for logs
        }
        if (!br.message.empty()) Console::Info(br.message);

        InstalledRecord rec;
        rec.packageId = c.package->id;
        rec.name = c.package->name;
        rec.scope = ScopeName(c.scope);
        rec.version = c.release->version;
        rec.arch = ArchName(c.installer->arch);
        rec.installerType = InstallerTypeName(c.installer->type);
        rec.repository = c.package->repository;
        rec.installLocation = br.installLocation;
        rec.installedAt = previous ? previous->installedAt : NowUnix();
        rec.updatedAt = NowUnix();
        rec.uninstall = br.uninstall;
        rec.installerSha256 = c.installer->sha256;
        rec.dependency = previous ? previous->dependency : dependency;
        rec.files = br.files;
        db_.Begin();
        try {
            if (previous && previous->scope != rec.scope) db_.RemoveInstalled(previous->packageId, previous->scope);
            db_.PutInstalled(rec);
            db_.FinishTransaction(txId, TxStateFor(br.status), br.message);
            db_.Commit();
        } catch (...) {
            db_.Rollback();
            throw;
        }
        Log::Info(action + " " + c.package->id + " " + c.release->version + " succeeded");
        Snapshot();
        res.ok = true;
        res.reboot = br.status == BackendResult::Status::RebootRequired;
        res.code = res.reboot ? kExitRebootRequired : kExitOk;
        if (!cfg_.GetBool("cache.keepDownloads")) {
            // lock is released when this scope ends; delete afterwards below
        }
        RemoveTree(tempDir);
    } catch (const Error& e) {
        finish(e.code() == kExitCancelled ? "cancelled" : "failed", e.what());
        RemoveTree(tempDir);
        throw;
    }
    if (!cfg_.GetBool("cache.keepDownloads")) {
        std::string dir = JoinPath(JoinPath(GetAppPaths().cacheDir, "downloads"), c.package->id);
        RemoveTree(dir);
    }
    return res;
}

int Engine::Install(const std::string& id, const EngineOptions& o, Json& out) {
    Console::Step("Resolving package");
    const Package* pkg = repos_.Find(id);
    if (!pkg) {
        Console::StepResult("NOT FOUND", Color::Red);
        throw Error(kExitNotFound, "package '" + id + "' was not found in any enabled repository",
                    "try 'sevenget search " + id + "' or 'sevenget update'");
    }
    ResolveOptions ro = o.resolve;
    ResolveResult rr = ResolvePackage(*pkg, platform_, ro);
    if (!rr.ok) {
        Console::StepResult("FAILED", Color::Red);
        throw Error(rr.errorCode, rr.error);
    }
    const Candidate& c = rr.candidate;
    Console::StepResult(c.package->name + " " + c.release->version + " (" + ArchName(c.installer->arch) + ", " +
                            InstallerTypeName(c.installer->type) + ", " + ScopeName(c.scope) + ") from " +
                            c.package->repository,
                        Color::Green);
    Console::Step("Checking compatibility");
    Console::StepResult("OK (Windows NT " + std::to_string(platform_.winMajor) + "." + std::to_string(platform_.winMinor) +
                            " " + ArchName(platform_.nativeArch) + "; release requires NT " +
                            std::to_string(c.installer->minWinMajor) + "." + std::to_string(c.installer->minWinMinor) +
                            "+)",
                        Color::Green);
    for (const auto& s : rr.skipped) Console::Info("  newer release skipped - " + s);

    InstalledRecord existing;
    if (db_.GetInstalled(pkg->id, ScopeName(c.scope), existing) && !o.force) {
        int cmp = CompareVersions(existing.version, c.release->version);
        std::string msg = pkg->id + " " + existing.version + " is already installed (" + existing.scope + ")";
        if (cmp < 0) msg += "; run 'sevenget upgrade " + pkg->id + "' to get " + c.release->version;
        Console::Info(msg);
        out.Set("status", "already-installed");
        out.Set("installedVersion", existing.version);
        return kExitOk;
    }

    Console::Step("Resolving dependencies");
    DependencyPlan plan = ResolveDependencies(
        c, platform_, ro, [&](const std::string& d) { return repos_.Find(d); },
        [&](const std::string& d) { return InstalledVersion(d); });
    if (!plan.ok) {
        Console::StepResult("FAILED", Color::Red);
        throw Error(plan.errorCode, plan.error);
    }
    Console::StepResult(plan.steps.size() > 1 ? std::to_string(plan.steps.size() - 1) + " dependency(ies) to install"
                                              : "none",
                        Color::Green);
    Console::Step("Verifying repository metadata");
    Console::StepResult("OK (signature, sequence and expiry checked)", Color::Green);
    for (const auto& s : plan.steps) CheckPermissions(s.candidate);

    Json planJson = Json::Array();
    uint64_t totalSize = 0;
    Console::OutLine();
    Console::OutLine("The following package(s) will be installed:", Color::White);
    for (const auto& s : plan.steps) {
        planJson.Push(CandidateToJson(s.candidate));
        totalSize += s.candidate.installer->size;
        Console::OutLine("  " + s.candidate.package->id + " " + s.candidate.release->version + "  [" +
                         ArchName(s.candidate.installer->arch) + ", " + InstallerTypeName(s.candidate.installer->type) +
                         ", " + ScopeName(s.candidate.scope) + "]" + (s.dependency ? "  (dependency)" : "") +
                         (s.candidate.installer->size ? "  " + FormatBytes(s.candidate.installer->size) : ""));
        Console::OutLine("    " + s.candidate.installer->url, Color::Gray);
    }
    out.Set("plan", planJson);
    if (o.dryRun) {
        Console::OutLine();
        Console::OutLine("Dry run: nothing was downloaded or installed.");
        out.Set("status", "dry-run");
        return kExitOk;
    }
    WarnWindows7();
    if (!ConfirmPlan("Proceed with installation" + (totalSize ? " (" + FormatBytes(totalSize) + " download)" : std::string()) + "?", o)) {
        out.Set("status", "cancelled");
        throw Error(kExitCancelled, "installation cancelled by user");
    }
    Json results = Json::Array();
    int finalCode = kExitOk;
    for (const auto& s : plan.steps) {
        Console::Info("");
        Console::Info("Installing " + s.candidate.package->name + " " + s.candidate.release->version + "...");
        Outcome oc = ExecuteInstall(s.candidate, s.dependency, nullptr, "install");
        Json r = CandidateToJson(s.candidate);
        r.Set("ok", oc.ok);
        r.Set("rebootRequired", oc.reboot);
        if (!oc.message.empty()) r.Set("message", oc.message);
        results.Push(r);
        if (!oc.ok) {
            out.Set("results", results);
            throw Error(oc.code, s.candidate.package->id + ": " + oc.message);
        }
        if (oc.reboot) finalCode = kExitRebootRequired;
    }
    out.Set("results", results);
    out.Set("status", finalCode == kExitRebootRequired ? "reboot-required" : "installed");
    Console::OutLine(finalCode == kExitRebootRequired
                         ? "Installation completed. Restart Windows to finish."
                         : "Installation completed successfully.",
                     Color::Green);
    return finalCode;
}

int Engine::Upgrade(const std::vector<std::string>& ids, bool all, const EngineOptions& o, Json& out) {
    std::vector<InstalledRecord> targets;
    if (all) {
        targets = db_.ListInstalled();
    } else {
        for (const auto& id : ids) {
            auto recs = db_.FindInstalled(id);
            if (recs.empty()) throw Error(kExitNotFound, "'" + id + "' is not installed by SevenGet");
            for (auto& r : recs)
                if (!o.resolve.scopeSpecified || r.scope == ScopeName(o.resolve.scope)) targets.push_back(r);
        }
    }
    struct Item {
        InstalledRecord rec;
        Candidate cand;
    };
    std::vector<Item> work;
    Json upToDate = Json::Array();
    Json skipped = Json::Array();
    for (const auto& rec : targets) {
        const Package* pkg = repos_.Find(rec.packageId);
        if (!pkg) {
            Console::Info(rec.packageId + ": not available in any enabled repository; skipped");
            skipped.Push(rec.packageId);
            continue;
        }
        ResolveOptions ro = o.resolve;
        ro.scopeSpecified = true;
        ro.scope = rec.scope == "machine" ? Scope::Machine : Scope::User;
        if (o.resolve.arch == Arch::Unknown) ParseArch(rec.arch, ro.arch);
        InstallerType oldType;
        if (InstallerTypeFromName(rec.installerType, oldType)) {
            ro.typePreference.erase(std::remove(ro.typePreference.begin(), ro.typePreference.end(), oldType),
                                    ro.typePreference.end());
            ro.typePreference.insert(ro.typePreference.begin(), oldType);
        }
        ResolveResult rr = ResolvePackage(*pkg, platform_, ro);
        if (!rr.ok) {
            Console::Info(rec.packageId + ": " + rr.error);
            skipped.Push(rec.packageId);
            if (!all) throw Error(rr.errorCode, rr.error);
            continue;
        }
        int cmp = CompareVersions(rr.candidate.release->version, rec.version);
        if (cmp <= 0 && !(o.force && !o.resolve.version.empty())) {
            if (cmp < 0 && !o.resolve.version.empty())
                Console::Info(rec.packageId + ": " + o.resolve.version + " is older than the installed " + rec.version +
                              "; use --force to downgrade");
            else
                Console::Info(rec.packageId + " " + rec.version + " is up to date");
            upToDate.Push(rec.packageId);
            continue;
        }
        for (const auto& s : rr.skipped) Console::Info("  " + rec.packageId + ": newer release skipped - " + s);
        work.push_back({rec, rr.candidate});
    }
    out.Set("upToDate", upToDate);
    out.Set("skipped", skipped);
    if (work.empty()) {
        Console::OutLine("Nothing to upgrade.");
        out.Set("status", "up-to-date");
        return kExitOk;
    }
    Json planJson = Json::Array();
    Console::OutLine();
    Console::OutLine("The following package(s) will be upgraded:", Color::White);
    for (const auto& w : work) {
        Json j = CandidateToJson(w.cand);
        j.Set("fromVersion", w.rec.version);
        planJson.Push(j);
        Console::OutLine("  " + w.rec.packageId + "  " + w.rec.version + " -> " + w.cand.release->version + "  [" +
                         ArchName(w.cand.installer->arch) + ", " + InstallerTypeName(w.cand.installer->type) + ", " +
                         w.rec.scope + "]");
    }
    out.Set("plan", planJson);
    if (o.dryRun) {
        Console::OutLine("Dry run: nothing was downloaded or installed.");
        out.Set("status", "dry-run");
        return kExitOk;
    }
    for (const auto& w : work) CheckPermissions(w.cand);
    WarnWindows7();
    if (!ConfirmPlan("Proceed with upgrade?", o)) throw Error(kExitCancelled, "upgrade cancelled by user");
    Json results = Json::Array();
    int finalCode = kExitOk;
    for (const auto& w : work) {
        Console::Info("");
        Console::Info("Upgrading " + w.rec.packageId + " " + w.rec.version + " -> " + w.cand.release->version + "...");
        Outcome oc;
        try {
            oc = ExecuteInstall(w.cand, w.rec.dependency, &w.rec, "upgrade");
        } catch (const Error& e) {
            oc.code = e.code();
            oc.message = e.what();
            if (e.code() == kExitCancelled) throw;
        }
        Json r = CandidateToJson(w.cand);
        r.Set("fromVersion", w.rec.version);
        r.Set("ok", oc.ok);
        if (!oc.message.empty()) r.Set("message", oc.message);
        results.Push(r);
        if (!oc.ok) {
            Console::Error(w.rec.packageId + ": " + oc.message);
            finalCode = oc.code;
        } else if (oc.reboot && finalCode == kExitOk) {
            finalCode = kExitRebootRequired;
        }
    }
    out.Set("results", results);
    out.Set("status", finalCode == kExitOk ? "upgraded" : finalCode == kExitRebootRequired ? "reboot-required" : "failed");
    if (finalCode == kExitOk) Console::OutLine("Upgrade completed successfully.", Color::Green);
    else if (finalCode == kExitRebootRequired) Console::OutLine("Upgrade completed. Restart Windows to finish.", Color::Green);
    return finalCode;
}

int Engine::Uninstall(const std::string& id, const EngineOptions& o, Json& out) {
    auto recs = db_.FindInstalled(id);
    if (o.resolve.scopeSpecified) {
        recs.erase(std::remove_if(recs.begin(), recs.end(),
                                  [&](const InstalledRecord& r) { return r.scope != ScopeName(o.resolve.scope); }),
                   recs.end());
    }
    if (recs.empty())
        throw Error(kExitNotFound, "'" + id + "' is not installed by SevenGet",
                    "SevenGet only uninstalls software it installed itself (see 'sevenget list')");
    if (recs.size() > 1)
        throw Error(kExitUsage, "'" + id + "' is installed both per-user and machine-wide; specify --user or --machine");
    const InstalledRecord& rec = recs.front();

    // Refuse to break installed packages that depend on this one.
    std::vector<std::string> dependents;
    for (const auto& other : db_.ListInstalled()) {
        if (EqualsIgnoreCase(other.packageId, rec.packageId)) continue;
        const Package* p = repos_.Find(other.packageId);
        if (!p) continue;
        for (const auto& r : p->releases)
            if (r.version == other.version)
                for (const auto& d : r.dependencies)
                    if (EqualsIgnoreCase(d.id, rec.packageId)) dependents.push_back(other.packageId);
    }
    if (!dependents.empty() && !o.force)
        throw Error(kExitError, rec.packageId + " is required by: " + Join(dependents, ", "),
                    "uninstall those first, or pass --force");

    InstallerType t;
    if (!InstallerTypeFromName(rec.installerType, t)) throw Error(kExitDatabase, "corrupt installation record");
    Console::OutLine("The following package will be removed:", Color::White);
    Console::OutLine("  " + rec.packageId + " " + rec.version + "  [" + rec.arch + ", " + rec.installerType + ", " +
                     rec.scope + "]" + (rec.installLocation.empty() ? "" : "  " + rec.installLocation));
    Json target = Json::Object();
    target.Set("id", rec.packageId);
    target.Set("version", rec.version);
    target.Set("scope", rec.scope);
    target.Set("installerType", rec.installerType);
    out.Set("package", target);
    if (o.dryRun) {
        Console::OutLine("Dry run: nothing was removed.");
        out.Set("status", "dry-run");
        return kExitOk;
    }
    if (rec.scope == "machine" && !IsProcessElevated() && t != InstallerType::Zip)
        Console::Info("Administrator rights are required; Windows will show a UAC prompt.");
    if (!ConfirmPlan("Uninstall " + rec.packageId + "?", o)) throw Error(kExitCancelled, "uninstall cancelled by user");

    TransactionRecord tr;
    tr.action = "uninstall";
    tr.packageId = rec.packageId;
    tr.fromVersion = rec.version;
    tr.scope = rec.scope;
    int64_t txId = db_.StartTransaction(tr);
    Log::Info("uninstall " + rec.packageId + " " + rec.version + " started");
    Console::Info("Uninstalling " + rec.packageId + "...");
    auto backend = CreateBackend(t);
    BackendResult br = backend->Uninstall(rec);
    if (!br.Ok()) {
        db_.FinishTransaction(txId, TxStateFor(br.status), br.message);
        Log::Error("uninstall " + rec.packageId + " failed: " + br.message);
        throw Error(ExitFromStatus(br.status), "uninstall failed: " + br.message,
                    "the installation record was kept; nothing else was changed");
    }
    if (br.alreadyGone) Console::Warn(br.message);
    else if (!br.message.empty()) Console::Info(br.message);
    db_.Begin();
    try {
        db_.RemoveInstalled(rec.packageId, rec.scope);
        db_.FinishTransaction(txId, TxStateFor(br.status), br.message);
        db_.Commit();
    } catch (...) {
        db_.Rollback();
        throw;
    }
    Snapshot();
    Log::Info("uninstall " + rec.packageId + " succeeded");
    bool reboot = br.status == BackendResult::Status::RebootRequired;
    out.Set("status", reboot ? "reboot-required" : "uninstalled");
    Console::OutLine(reboot ? "Uninstalled. Restart Windows to finish." : "Uninstalled " + rec.packageId + " successfully.",
                     Color::Green);
    return reboot ? kExitRebootRequired : kExitOk;
}

int Engine::Download(const std::string& id, const EngineOptions& o, const std::string& outDir, Json& out) {
    const Package* pkg = repos_.Find(id);
    if (!pkg) throw Error(kExitNotFound, "package '" + id + "' was not found in any enabled repository");
    ResolveResult rr = ResolvePackage(*pkg, platform_, o.resolve);
    if (!rr.ok) throw Error(rr.errorCode, rr.error);
    const Candidate& c = rr.candidate;
    Console::Info("Selected " + c.package->id + " " + c.release->version + " (" + ArchName(c.installer->arch) + ", " +
                  InstallerTypeName(c.installer->type) + ")");
    for (const auto& s : rr.skipped) Console::Info("  newer release skipped - " + s);
    out.Set("package", CandidateToJson(c));
    std::string dest = GetFullPath(JoinPath(outDir.empty() ? "." : outDir,
                                            c.package->id + "-" + c.release->version + "-" + ArchName(c.installer->arch) +
                                                ExtensionFor(c.installer->type)));
    out.Set("path", dest);
    if (o.dryRun) {
        Console::OutLine("Dry run: would download " + c.installer->url + " to " + dest);
        out.Set("status", "dry-run");
        return kExitOk;
    }
    Json info = Json::Object();
    std::string file = FetchVerified(c, info);
    out.Set("verification", info);
    if (!CreateDirectories(ParentPath(dest)) || !CopyFileW(Widen(file).c_str(), Widen(dest).c_str(), FALSE))
        throw Error(kExitError, "cannot write " + dest + ": " + LastErrorMessage(GetLastError()));
    // Re-verify the copy.
    std::string hex, err;
    if (!Sha256File(dest, hex, err) || !DigestEquals(hex, c.installer->sha256)) {
        DeleteFileUtf8(dest);
        throw Error(kExitIntegrity, "copied file failed verification");
    }
    if (!cfg_.GetBool("cache.keepDownloads")) DeleteFileUtf8(file);
    out.Set("status", "downloaded");
    Console::OutLine("Saved verified package to " + dest, Color::Green);
    return kExitOk;
}

}  // namespace sg
