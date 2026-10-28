// MSI backend: installs through msiexec.exe (never through a shell) and owns
// the product by its ProductCode, which is read from the verified package.
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

#include "install/backend.h"
#include "platform/console.h"
#include "platform/process.h"
#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

namespace {

std::string MsiExecPath() {
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    return JoinPath(Narrow(sys), "msiexec.exe");
}

bool ReadMsiProperty(const std::string& msiPath, const char* prop, std::string& out) {
    MSIHANDLE db = 0;
    if (MsiOpenDatabaseW(Widen(msiPath).c_str(), MSIDBOPEN_READONLY, &db) != ERROR_SUCCESS) return false;
    MSIHANDLE view = 0, rec = 0;
    bool ok = false;
    std::wstring q = L"SELECT `Value` FROM `Property` WHERE `Property`='" + Widen(prop) + L"'";
    if (MsiDatabaseOpenViewW(db, q.c_str(), &view) == ERROR_SUCCESS && MsiViewExecute(view, 0) == ERROR_SUCCESS &&
        MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
        wchar_t buf[512];
        DWORD len = 512;
        if (MsiRecordGetStringW(rec, 1, buf, &len) == ERROR_SUCCESS) {
            out = Narrow(std::wstring(buf, len));
            ok = true;
        }
    }
    if (rec) MsiCloseHandle(rec);
    if (view) MsiCloseHandle(view);
    MsiCloseHandle(db);
    return ok;
}

bool IsProductInstalled(const std::string& code) {
    return MsiQueryProductStateW(Widen(code).c_str()) == INSTALLSTATE_DEFAULT;
}

std::string ProductInfo(const std::string& code, const wchar_t* prop) {
    wchar_t buf[MAX_PATH * 2];
    DWORD len = MAX_PATH * 2;
    if (MsiGetProductInfoW(Widen(code).c_str(), prop, buf, &len) != ERROR_SUCCESS) return {};
    return Narrow(std::wstring(buf, len));
}

BackendResult RunMsiexec(const std::string& args, bool machine, const char* verb) {
    BackendResult r;
    ProcessResult pr = RunProcessRaw(MsiExecPath(), args, machine ? Elevation::Always : Elevation::Never, {},
                                     [] { Console::Warn("Ctrl+C received; waiting for Windows Installer to finish"); });
    if (!pr.started) {
        r.status = pr.startError == ERROR_CANCELLED ? BackendResult::Status::ElevationDenied
                                                    : BackendResult::Status::Failed;
        r.message = pr.startError == ERROR_CANCELLED ? "administrator permission was not granted"
                                                     : "could not start msiexec: " + LastErrorMessage(pr.startError);
        return r;
    }
    r.exitCode = pr.exitCode;
    r.status = ClassifyExitCode(pr.exitCode, {0}, {3010, 1641});
    if (!r.Ok()) r.message = std::string("Windows Installer ") + verb + " failed with " + DescribeInstallerExitCode(pr.exitCode);
    return r;
}

class MsiBackend : public InstallerBackend {
public:
    InstallerType type() const override { return InstallerType::Msi; }

    BackendResult Install(const InstallContext& ctx) override {
        BackendResult r;
        const Installer& in = *ctx.installer;
        std::string productCode;
        if (!ReadMsiProperty(ctx.packageFile, "ProductCode", productCode) || !IsValidGuid(productCode)) {
            r.status = BackendResult::Status::IntegrityFailed;
            r.message = "the MSI package has no valid ProductCode";
            return r;
        }
        if (!in.productCode.empty() && !EqualsIgnoreCase(in.productCode, productCode)) {
            r.status = BackendResult::Status::IntegrityFailed;
            r.message = "MSI ProductCode " + productCode + " does not match the manifest (" + in.productCode + ")";
            return r;
        }
        if (IsProductInstalled(productCode) && !ctx.previous) {
            r.status = BackendResult::Status::Failed;
            r.message = "this exact product (" + productCode + ") is already installed on this system outside SevenGet";
            return r;
        }
        bool machine = ctx.scope == Scope::Machine;
        std::string log = JoinPath(ctx.tempDir, "msiexec-install.log");
        std::string args = "/i " + QuoteArgument(ctx.packageFile) + " /qn /norestart /l*v " + QuoteArgument(log);
        args += machine ? " ALLUSERS=1" : " ALLUSERS=2 MSIINSTALLPERUSER=1";
        for (const auto& prop : in.silentArgs) {
            size_t eq = prop.find('=');
            args += " " + MsiPropertyArg(prop.substr(0, eq), prop.substr(eq + 1));
        }
        if (ctx.status)
            ctx.status(machine && !IsProcessElevated()
                           ? "Running Windows Installer (Windows will ask for administrator permission)..."
                           : "Running Windows Installer...");
        r = RunMsiexec(args, machine, "installation");
        if (!r.Ok()) {
            if (FileExists(log)) r.message += " (log: " + log + ")";
            return r;
        }
        if (!IsProductInstalled(productCode)) {
            r.status = BackendResult::Status::Failed;
            r.message = "msiexec reported success but product " + productCode + " is not installed";
            return r;
        }
        r.installLocation = ProductInfo(productCode, INSTALLPROPERTY_INSTALLLOCATION);
        Json u = Json::Object();
        u.Set("strategy", "msi");
        u.Set("productCode", productCode);
        u.Set("machine", machine);
        r.uninstall = u;
        return r;
    }

    bool IsPresent(const InstalledRecord& rec) override {
        const Json* pc = rec.uninstall.Find("productCode");
        return pc && pc->IsString() && IsProductInstalled(pc->AsString());
    }

    BackendResult Uninstall(const InstalledRecord& rec) override {
        BackendResult r;
        const Json* pc = rec.uninstall.Find("productCode");
        if (!pc || !pc->IsString() || !IsValidGuid(pc->AsString())) {
            r.message = "installation record has no valid ProductCode";
            return r;
        }
        std::string code = pc->AsString();
        if (!IsProductInstalled(code)) {
            r.status = BackendResult::Status::Success;
            r.alreadyGone = true;
            r.message = "the product had already been removed outside SevenGet";
            return r;
        }
        std::string log = JoinPath(GetAppPaths().logDir, "msiexec-uninstall-" + std::to_string(NowUnix()) + ".log");
        CreateDirectories(GetAppPaths().logDir);
        std::string args = "/x " + code + " /qn /norestart /l*v " + QuoteArgument(log);
        r = RunMsiexec(args, rec.scope == "machine", "uninstallation");
        if (!r.Ok()) return r;
        if (IsProductInstalled(code)) {
            r.status = BackendResult::Status::Failed;
            r.message = "msiexec reported success but the product is still installed";
        }
        return r;
    }
};

}  // namespace

std::unique_ptr<InstallerBackend> CreateMsiBackend() { return std::unique_ptr<InstallerBackend>(new MsiBackend()); }

}  // namespace sg
