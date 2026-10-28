// ZIP backend: portable packages extracted by SevenGet itself into
//   per-user:     %LOCALAPPDATA%\SevenGet\apps\<package-id>
//   machine-wide: %ProgramFiles%\SevenGet Apps\<package-id>  (elevated prompt required)
// Extraction goes to a staging directory which is swapped into place with
// directory renames, so a failed or interrupted upgrade leaves the previous
// version intact. Ownership is the list of extracted files.
#include <windows.h>

#include "install/backend.h"
#include "install/zip_extract.h"
#include "platform/console.h"
#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

namespace {

std::string AppsRoot(Scope s) { return s == Scope::Machine ? GetAppPaths().machineAppsDir : GetAppPaths().userAppsDir; }

// Returns files under root that are open by another process (cannot be
// opened for DELETE without sharing).
std::vector<std::string> LockedFiles(const std::string& root, const std::vector<std::string>& rels) {
    std::vector<std::string> locked;
    for (const auto& rel : rels) {
        std::string full = JoinPath(root, rel);
        HANDLE h = CreateFileW(Widen(full).c_str(), DELETE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION) locked.push_back(rel);
            continue;
        }
        CloseHandle(h);
    }
    return locked;
}

void RemoveEmptyDirs(const std::string& dir) {
    for (const auto& name : ListDirectory(dir)) {
        std::string p = JoinPath(dir, name);
        if (DirExists(p)) {
            DWORD a = GetFileAttributesW(Widen(p).c_str());
            if (!(a & FILE_ATTRIBUTE_REPARSE_POINT)) RemoveEmptyDirs(p);
        }
    }
    RemoveDirectoryW(Widen(dir).c_str());  // fails harmlessly if not empty
}

void ListFilesRecursive(const std::string& root, const std::string& rel, std::vector<std::string>& out) {
    for (const auto& name : ListDirectory(rel.empty() ? root : JoinPath(root, rel))) {
        std::string r = rel.empty() ? name : rel + "\\" + name;
        std::string full = JoinPath(root, r);
        DWORD a = GetFileAttributesW(Widen(full).c_str());
        if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (a & FILE_ATTRIBUTE_DIRECTORY) ListFilesRecursive(root, r, out);
        else out.push_back(r);
    }
}

// Files the user created inside a portable app directory (settings, data)
// were not installed by SevenGet; carry them over to the new version.
void PreserveUserFiles(const std::string& oldRoot, const std::string& newRoot, const InstalledRecord* previous,
                       const std::vector<std::string>& newFiles) {
    if (!previous) return;
    auto contains = [](const std::vector<std::string>& v, const std::string& s) {
        for (const auto& x : v)
            if (EqualsIgnoreCase(x, s)) return true;
        return false;
    };
    std::vector<std::string> all;
    ListFilesRecursive(oldRoot, "", all);
    for (const auto& rel : all) {
        if (contains(previous->files, rel) || contains(newFiles, rel)) continue;
        std::string dest = JoinPath(newRoot, rel);
        CreateDirectories(ParentPath(dest));
        if (!MoveFileExW(Widen(JoinPath(oldRoot, rel)).c_str(), Widen(dest).c_str(), MOVEFILE_COPY_ALLOWED))
            Console::Warn("could not carry over user file " + rel);
    }
}

class ZipBackend : public InstallerBackend {
public:
    InstallerType type() const override { return InstallerType::Zip; }

    BackendResult Install(const InstallContext& ctx) override {
        BackendResult r;
        const Installer& in = *ctx.installer;
        if (ctx.scope == Scope::Machine && !IsProcessElevated()) {
            r.status = BackendResult::Status::ElevationDenied;
            r.message = "machine-wide portable installs write to Program Files; run SevenGet from an elevated "
                        "Command Prompt or use --user";
            return r;
        }
        std::string appsRoot = AppsRoot(ctx.scope);
        if (!CreateDirectories(appsRoot)) {
            r.message = "cannot create " + appsRoot + ": " + LastErrorMessage(GetLastError());
            r.status = GetLastError() == ERROR_ACCESS_DENIED ? BackendResult::Status::ElevationDenied
                                                             : BackendResult::Status::Failed;
            return r;
        }
        std::string target = JoinPath(appsRoot, ctx.package->id);
        if (!IsPathInside(appsRoot, target)) {
            r.message = "refusing to install outside " + appsRoot;
            return r;
        }
        std::string suffix = std::to_string(GetCurrentProcessId());
        std::string staging = target + ".staging-" + suffix;
        RemoveTree(staging);
        if (!CreateDirectories(staging)) {
            r.message = "cannot create staging directory " + staging;
            return r;
        }
        if (ctx.status) ctx.status("Extracting...");
        ZipResult z = ExtractZip(ctx.packageFile, staging);
        if (!z.ok) {
            RemoveTree(staging);
            r.status = CancelRequested() ? BackendResult::Status::Cancelled : BackendResult::Status::IntegrityFailed;
            r.message = z.error;
            return r;
        }
        // Authenticode verification of the binaries inside the archive.
        if (in.signature.required || ctx.requireAuthenticode) {
            if (in.signature.files.empty()) {
                RemoveTree(staging);
                r.status = BackendResult::Status::IntegrityFailed;
                r.message = "Authenticode signatures are required but the manifest lists no signed files";
                return r;
            }
        }
        for (const auto& f : in.signature.files) {
            std::string rel, why;
            bool isDir;
            std::string match;
            if (SanitizeZipEntryName(f, rel, isDir, why))
                for (const auto& extracted : z.files)
                    if (EqualsIgnoreCase(extracted, rel)) match = extracted;
            if (match.empty()) {
                RemoveTree(staging);
                r.status = BackendResult::Status::IntegrityFailed;
                r.message = "signed file '" + f + "' listed in the manifest is missing from the archive";
                return r;
            }
            AuthenticodeResult ar = VerifyAuthenticode(JoinPath(staging, match), ctx.revocation);
            bool subjectOk = in.signature.subject.empty() || EqualsIgnoreCase(ar.signerSubject, in.signature.subject);
            bool mustPass = in.signature.required || ctx.requireAuthenticode;
            if (ar.status == AuthenticodeResult::Status::Valid && subjectOk) {
                if (ctx.status) ctx.status("Authenticode " + match + ": valid, signed by " + ar.signerSubject +
                                           (ar.revocationUnchecked ? " (revocation not checked)" : ""));
            } else if (mustPass) {
                RemoveTree(staging);
                r.status = BackendResult::Status::IntegrityFailed;
                r.message = "Authenticode verification of " + match + " failed: " +
                            (subjectOk ? ar.message : "signed by '" + ar.signerSubject + "', expected '" + in.signature.subject + "'");
                return r;
            } else {
                Console::Warn("Authenticode check of " + match + ": " + ar.message +
                              " (not required; integrity is guaranteed by the SHA-256 from signed metadata)");
            }
        }
        // Swap into place.
        std::string backup;
        if (DirExists(target)) {
            backup = target + ".old-" + suffix;
            RemoveTree(backup);
            if (!MoveFileExW(Widen(target).c_str(), Widen(backup).c_str(), 0)) {
                DWORD e = GetLastError();
                RemoveTree(staging);
                r.status = BackendResult::Status::Failed;
                r.message = "cannot replace " + target + " (" + LastErrorMessage(e) +
                            "); close programs running from it and try again";
                return r;
            }
        }
        if (!MoveFileExW(Widen(staging).c_str(), Widen(target).c_str(), 0)) {
            DWORD e = GetLastError();
            if (!backup.empty()) MoveFileExW(Widen(backup).c_str(), Widen(target).c_str(), 0);
            RemoveTree(staging);
            r.status = BackendResult::Status::Failed;
            r.message = "cannot activate new files in " + target + ": " + LastErrorMessage(e);
            return r;
        }
        if (!backup.empty()) PreserveUserFiles(backup, target, ctx.previous, z.files);
        if (!backup.empty() && !RemoveTree(backup))
            Console::Warn("could not fully remove previous version at " + backup + "; remove it manually");
        r.status = BackendResult::Status::Success;
        r.installLocation = target;
        r.files = z.files;
        Json u = Json::Object();
        u.Set("strategy", "files");
        u.Set("root", target);
        r.uninstall = u;
        return r;
    }

    bool IsPresent(const InstalledRecord& rec) override {
        const Json* root = rec.uninstall.Find("root");
        return root && root->IsString() && DirExists(root->AsString());
    }

    BackendResult Uninstall(const InstalledRecord& rec) override {
        BackendResult r;
        const Json* rootJ = rec.uninstall.Find("root");
        if (!rootJ || !rootJ->IsString()) {
            r.message = "installation record has no install root";
            return r;
        }
        std::string root = rootJ->AsString();
        Scope scope = rec.scope == "machine" ? Scope::Machine : Scope::User;
        // Defense in depth: never delete outside SevenGet's own app directory.
        if (!IsPathInside(AppsRoot(scope), root) || EqualsIgnoreCase(GetFullPath(root), GetFullPath(AppsRoot(scope)))) {
            r.message = "recorded install root " + root + " is outside SevenGet's application directory; refusing";
            return r;
        }
        if (!DirExists(root)) {
            r.status = BackendResult::Status::Success;
            r.alreadyGone = true;
            r.message = "the package directory had already been removed";
            return r;
        }
        if (scope == Scope::Machine && !IsProcessElevated()) {
            r.status = BackendResult::Status::ElevationDenied;
            r.message = "removing a machine-wide portable package requires an elevated Command Prompt";
            return r;
        }
        std::vector<std::string> safe;
        for (const auto& rel : rec.files) {
            std::string clean, why;
            bool isDir;
            if (SanitizeZipEntryName(rel, clean, isDir, why) && IsPathInside(root, JoinPath(root, clean)))
                safe.push_back(clean);
        }
        auto locked = LockedFiles(root, safe);
        if (!locked.empty()) {
            r.status = BackendResult::Status::Failed;
            r.message = "files are in use: " + Join(locked, ", ") + " - close the program and try again";
            return r;
        }
        std::vector<std::string> failed;
        for (const auto& rel : safe) {
            std::string full = JoinPath(root, rel);
            if (FileExists(full) && !DeleteFileUtf8(full)) failed.push_back(rel);
        }
        RemoveEmptyDirs(root);
        if (!failed.empty()) {
            r.status = BackendResult::Status::Failed;
            r.message = "could not delete: " + Join(failed, ", ");
            return r;
        }
        r.status = BackendResult::Status::Success;
        if (DirExists(root))
            r.message = "files not installed by SevenGet were left in " + root;
        return r;
    }
};

}  // namespace

std::unique_ptr<InstallerBackend> CreateZipBackend() { return std::unique_ptr<InstallerBackend>(new ZipBackend()); }

}  // namespace sg
