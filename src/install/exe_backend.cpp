// EXE installer backend: runs the vendor installer with the manifest's
// documented silent switches and takes ownership of exactly one Uninstall
// registry key (named in the manifest).
#include <windows.h>

#include "install/backend.h"
#include "platform/console.h"
#include "platform/process.h"
#include "platform/winutil.h"
#include "util/strings.h"
#include "util/version.h"

namespace sg {

namespace {

const char kUninstallRoot[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";

struct RegLocation {
    std::string hive;
    int view = 0;
    bool found = false;
};

std::vector<RegLocation> CandidateLocations(Scope scope, Arch arch) {
    std::string primary = scope == Scope::Machine ? "HKLM" : "HKCU";
    std::string secondary = scope == Scope::Machine ? "HKCU" : "HKLM";
    std::vector<int> views;
    if (GetOsInfo().nativeArch == Arch::X64) {
        views = arch == Arch::X86 ? std::vector<int>{32, 64} : std::vector<int>{64, 32};
    } else {
        views = {0};
    }
    std::vector<RegLocation> out;
    for (const auto& h : {primary, secondary})
        for (int v : views) out.push_back({h, v, false});
    return out;
}

RegLocation FindKey(const std::string& keyName, Scope scope, Arch arch) {
    for (auto loc : CandidateLocations(scope, arch)) {
        if (RegKeyExists(loc.hive, kUninstallRoot + keyName, loc.view)) {
            loc.found = true;
            return loc;
        }
    }
    return {};
}

std::string ReadValue(const RegLocation& loc, const std::string& key, const char* value) {
    std::string out;
    RegReadString(loc.hive, kUninstallRoot + key, value, out, loc.view);
    return out;
}

class ExeBackend : public InstallerBackend {
public:
    InstallerType type() const override { return InstallerType::Exe; }

    BackendResult Install(const InstallContext& ctx) override {
        BackendResult r;
        const Installer& in = *ctx.installer;
        const std::string& key = in.uninstall.registryKey;
        Elevation elev = ctx.scope == Scope::Machine ? Elevation::Always : Elevation::IfRequired;
        if (ctx.status)
            ctx.status(ctx.scope == Scope::Machine && !IsProcessElevated()
                           ? "Running installer (Windows will ask for administrator permission)..."
                           : "Running installer...");
        ProcessResult pr = RunProcess(ctx.packageFile, in.silentArgs, elev, ctx.tempDir, [] {
            Console::Warn("Ctrl+C received; waiting for the installer to finish (stopping it midway could damage the installation)");
        });
        if (!pr.started) {
            if (pr.startError == ERROR_CANCELLED) {
                r.status = BackendResult::Status::ElevationDenied;
                r.message = "administrator permission was not granted";
            } else {
                r.status = BackendResult::Status::Failed;
                r.message = "could not start installer: " + LastErrorMessage(pr.startError);
            }
            return r;
        }
        r.exitCode = pr.exitCode;
        r.status = ClassifyExitCode(pr.exitCode, in.successExitCodes, in.rebootExitCodes);
        if (!r.Ok()) {
            r.message = "installer failed with " + DescribeInstallerExitCode(pr.exitCode);
            return r;
        }
        // Verify the installer actually registered the product.
        RegLocation loc;
        for (int i = 0; i < 20 && !loc.found; ++i) {
            loc = FindKey(key, ctx.scope, in.arch);
            if (!loc.found) Sleep(250);
        }
        if (!loc.found) {
            r.status = BackendResult::Status::Failed;
            r.message = "installer exited with " + DescribeInstallerExitCode(pr.exitCode) +
                        " but did not create its uninstall registration '" + key + "'; not recording the installation";
            return r;
        }
        std::string displayVersion = ReadValue(loc, key, "DisplayVersion");
        if (!displayVersion.empty() && IsValidVersionString(displayVersion) &&
            CompareVersions(displayVersion, ctx.release->version) != 0)
            r.message = "note: installed product reports version " + displayVersion;
        r.installLocation = ReadValue(loc, key, "InstallLocation");
        Json u = Json::Object();
        u.Set("strategy", "registry");
        u.Set("hive", loc.hive);
        u.Set("view", loc.view);
        u.Set("registryKey", key);
        u.Set("uninstallString", ReadValue(loc, key, "UninstallString"));
        u.Set("quietUninstallString", ReadValue(loc, key, "QuietUninstallString"));
        Json qa = Json::Array();
        for (const auto& a : in.uninstall.quietArgs) qa.Push(a);
        u.Set("quietArgs", qa);
        u.Set("displayName", ReadValue(loc, key, "DisplayName"));
        r.uninstall = u;
        return r;
    }

    bool IsPresent(const InstalledRecord& rec) override {
        const Json& u = rec.uninstall;
        const Json* key = u.Find("registryKey");
        const Json* hive = u.Find("hive");
        const Json* view = u.Find("view");
        if (!key || !hive || !view) return false;
        return RegKeyExists(hive->AsString(), kUninstallRoot + key->AsString(), static_cast<int>(view->AsInt()));
    }

    BackendResult Uninstall(const InstalledRecord& rec) override {
        BackendResult r;
        const Json& u = rec.uninstall;
        auto str = [&](const char* k) {
            const Json* v = u.Find(k);
            return v && v->IsString() ? v->AsString() : std::string();
        };
        RegLocation loc;
        loc.hive = str("hive");
        const Json* view = u.Find("view");
        loc.view = view && view->IsInteger() ? static_cast<int>(view->AsInt()) : 0;
        std::string key = str("registryKey");
        if (key.empty() || (loc.hive != "HKLM" && loc.hive != "HKCU")) {
            r.message = "installation record has no usable uninstall information";
            return r;
        }
        if (!RegKeyExists(loc.hive, kUninstallRoot + key, loc.view)) {
            r.status = BackendResult::Status::Success;
            r.alreadyGone = true;
            r.message = "the product had already been removed outside SevenGet";
            return r;
        }
        // Use the live registration, but only if it still belongs to the
        // program SevenGet installed (same uninstaller executable).
        std::string quiet = ReadValue(loc, key, "QuietUninstallString");
        std::string normal = ReadValue(loc, key, "UninstallString");
        std::vector<std::string> recordedArgv = SplitCommandLine(str("uninstallString"));
        std::vector<std::string> argv;
        bool interactive = false;
        if (!quiet.empty()) {
            argv = SplitCommandLine(quiet);
        } else if (!normal.empty()) {
            argv = SplitCommandLine(normal);
            const Json* qa = u.Find("quietArgs");
            if (qa && qa->IsArray() && qa->Size() > 0) {
                for (const auto& a : qa->Items()) argv.push_back(a.AsString());
            } else {
                interactive = true;
            }
        }
        if (argv.empty() || argv[0].empty()) {
            r.message = "the product's uninstall registration has no uninstall command";
            return r;
        }
        std::string exe = ExpandEnv(argv[0]);
        if (!recordedArgv.empty() && !EqualsIgnoreCase(GetFullPath(ExpandEnv(recordedArgv[0])), GetFullPath(exe))) {
            r.message = "the uninstall registration '" + key + "' now points to a different program (" + exe +
                        ") than the one SevenGet installed; refusing to run it";
            return r;
        }
        if (exe.size() < 3 || exe[1] != ':' || !FileExists(exe)) {
            r.message = "uninstaller not found: " + exe;
            return r;
        }
        if (IsForbiddenUninstallHost(exe)) {
            r.message = "refusing to run uninstall command through " + FileName(exe);
            return r;
        }
        if (interactive)
            Console::Warn("this package's uninstaller has no documented silent mode; its window will appear");
        argv.erase(argv.begin());
        Elevation elev = loc.hive == "HKLM" ? Elevation::Always : Elevation::IfRequired;
        ProcessResult pr = RunProcess(exe, argv, elev, ParentPath(exe), [] {
            Console::Warn("Ctrl+C received; waiting for the uninstaller to finish");
        });
        if (!pr.started) {
            r.status = pr.startError == ERROR_CANCELLED ? BackendResult::Status::ElevationDenied
                                                        : BackendResult::Status::Failed;
            r.message = pr.startError == ERROR_CANCELLED ? "administrator permission was not granted"
                                                         : "could not start uninstaller: " + LastErrorMessage(pr.startError);
            return r;
        }
        r.exitCode = pr.exitCode;
        r.status = ClassifyExitCode(pr.exitCode, {0}, {3010, 1641});
        if (!r.Ok()) {
            r.message = "uninstaller failed with " + DescribeInstallerExitCode(pr.exitCode);
            return r;
        }
        // Some uninstallers hand off to a copy of themselves and exit early.
        for (int i = 0; i < 240; ++i) {
            if (!RegKeyExists(loc.hive, kUninstallRoot + key, loc.view)) return r;
            Sleep(500);
        }
        r.status = BackendResult::Status::Failed;
        r.message = "the uninstaller finished but the product is still registered";
        return r;
    }

private:
    static std::string ExpandEnv(const std::string& s) {
        std::wstring w = Widen(s);
        DWORD n = ExpandEnvironmentStringsW(w.c_str(), nullptr, 0);
        if (!n) return s;
        std::wstring buf(n, L'\0');
        ExpandEnvironmentStringsW(w.c_str(), &buf[0], n);
        buf.resize(wcsnlen(buf.c_str(), buf.size()));
        return Narrow(buf);
    }
};

}  // namespace

std::unique_ptr<InstallerBackend> CreateExeBackend() { return std::unique_ptr<InstallerBackend>(new ExeBackend()); }

}  // namespace sg
