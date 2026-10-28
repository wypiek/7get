// CLI parsing tests and an offline end-to-end scenario: enroll a local signed
// repository, install a portable (zip) package, upgrade, detect rollback,
// handle locked files and uninstall. The package file is pre-seeded into the
// download cache so no network is required; it is still SHA-256 verified.
#include <windows.h>

#include "cli/args.h"
#include "cli/commands.h"
#include "core/database.h"
#include "core/repository.h"
#include "platform/crypto.h"
#include "platform/winutil.h"
#include "test.h"
#include "util/error.h"
#include "util/strings.h"

using namespace sg;

TEST(args_parsing) {
    ParseError e;
    ParsedArgs a = ParseArgs({"install", "7zip.7zip", "--version", "23.01", "--arch=x86", "-y", "--user"}, e);
    CHECK(!e.failed);
    CHECK_EQ(a.command, std::string("install"));
    CHECK(a.positional.size() == 1 && a.positional[0] == "7zip.7zip");
    CHECK_EQ(a.version, std::string("23.01"));
    CHECK_EQ(a.arch, std::string("x86"));
    CHECK(a.yes && a.user && !a.showVersion);

    ParseError e2;
    ParsedArgs b = ParseArgs({"--version"}, e2);
    CHECK(!e2.failed && b.showVersion);

    ParseError e3;
    ParseArgs({"install", "x", "--version"}, e3);
    CHECK(e3.failed);  // missing value

    ParseError e4;
    ParseArgs({"install", "x", "--bogus"}, e4);
    CHECK(e4.failed);

    ParseError e5;
    ParseArgs({"install", "x", "--user", "--machine"}, e5);
    CHECK(e5.failed);

    ParseError e6;
    ParsedArgs f = ParseArgs({"search", "--", "--weird name"}, e6);
    CHECK(!e6.failed && f.positional.size() == 1 && f.positional[0] == "--weird name");

    ParseError e7;
    ParseArgs({"list", "--json=yes"}, e7);
    CHECK(e7.failed);
}

TEST(cli_usage_errors_and_config) {
    CHECK_EQ(RunCli({"help"}), kExitOk);
    CHECK_EQ(RunCli({"help", "install"}), kExitOk);
    CHECK_EQ(RunCli({"version", "--json"}), kExitOk);
    CHECK_EQ(RunCli({"frobnicate"}), kExitUsage);
    CHECK_EQ(RunCli({"install"}), kExitUsage);
    CHECK_EQ(RunCli({"upgrade"}), kExitUsage);
    CHECK_EQ(RunCli({"upgrade", "a", "--all"}), kExitUsage);
    CHECK_EQ(RunCli({"config", "set", "arch", "mips"}), kExitUsage);
    CHECK_EQ(RunCli({"config", "set", "no.such.key", "1"}), kExitUsage);
    CHECK_EQ(RunCli({"config", "set", "network.timeoutSeconds", "1"}), kExitUsage);
    CHECK_EQ(RunCli({"config", "set", "network.timeoutSeconds", "30", "--quiet"}), kExitOk);
    CHECK_EQ(RunCli({"config", "get", "network.timeoutSeconds"}), kExitOk);
    CHECK_EQ(RunCli({"config", "list", "--json"}), kExitOk);
    CHECK_EQ(RunCli({"config", "set", "network.timeoutSeconds", "60"}), kExitOk);
    CHECK_EQ(RunCli({"repo", "add", "http://insecure.example/repo", "--yes", "--fingerprint", "00"}), kExitUsage);
    CHECK_EQ(RunCli({"repo", "add", "https://example.invalid/repo", "--yes"}), kExitUsage);  // no silent TOFU
    CHECK_EQ(RunCli({"uninstall", "Not.Installed", "--yes"}), kExitNotFound);
    CHECK_EQ(RunCli({"repo", "remove", "nothing", "--yes"}), kExitNotFound);
}

namespace {

struct LocalRepo {
    std::string dir;
    PrivateKey priv;
    PublicKey pub;
    std::string zipSha;
    uint64_t zipSize = 0;

    bool Init(const std::string& d) {
        dir = d;
        std::string err;
        if (!GenerateKeyPair(priv, pub, err)) return false;
        WriteFileAtomic(JoinPath(dir, "key.pub"), FormatPublicKey(pub) + "\n");
        if (!Sha256File(sgtest::DataPath("good.zip"), zipSha, err)) return false;
        zipSize = FileSize(sgtest::DataPath("good.zip"));
        return true;
    }

    std::string Manifest(const std::string& version, const std::string& sha) const {
        return R"({"id": "Test.Portable", "name": "Test Portable", "publisher": "SevenGet tests",
          "description": "Portable test package", "license": "MIT", "tags": ["portable"],
          "releases": [{"version": ")" + version + R"(", "installers": [
            {"arch": "x86", "type": "zip", "url": "https://example.invalid/test-portable.zip",
             "sha256": ")" + sha + R"(", "size": )" + std::to_string(zipSize) + R"(,
             "minWindows": "6.1", "scope": ["user", "machine"], "uninstall": {"strategy": "files"}}]}]})";
    }

    std::string Publish(int64_t seq, const std::string& version, const std::string& sha) {
        std::string idx = "{\"schema\": 1, \"repository\": \"local-test\", \"sequence\": " + std::to_string(seq) +
                          ", \"generated\": \"" + FormatUtc(NowUnix() - 60) + "\", \"expires\": \"" +
                          FormatUtc(NowUnix() + 86400 * 30) + "\", \"packages\": [" + Manifest(version, sha) + "]}";
        Bytes sig;
        std::string err;
        SignEcdsaP256(priv, idx, sig, err);
        WriteFileAtomic(JoinPath(dir, "index.json"), idx);
        WriteFileAtomic(JoinPath(dir, "index.json.sig"), FormatSignatureFile(pub, sig));
        return idx;
    }

    // Places the verified package where the engine's download cache expects it.
    void SeedCache(const std::string& version, const std::string& content) const {
        std::string d = JoinPath(JoinPath(JoinPath(GetAppPaths().cacheDir, "downloads"), "Test.Portable"), version);
        CreateDirectories(d);
        WriteFileAtomic(JoinPath(d, "x86-" + zipSha.substr(0, 12) + ".zip"), content);
    }
};

std::string ReadAll(const std::string& p) {
    std::string s;
    ReadFileBytes(p, s);
    return s;
}

}  // namespace

TEST(cli_end_to_end_local_repository_zip_package) {
    std::string repoDir = sgtest::TempDir("local repo \xC3\xA9");
    LocalRepo repo;
    if (!repo.Init(repoDir)) {
        ::sgtest::ReportFailure(__FILE__, __LINE__, "repository setup failed");
        return;
    }
    repo.Publish(1, "1.0", repo.zipSha);
    std::string fp = repo.pub.Fingerprint();

    // Wrong fingerprint is rejected; correct one enrolls.
    CHECK_EQ(RunCli({"repo", "add", repoDir, "--yes", "--fingerprint", std::string(64, '0'), "--quiet"}), kExitTrust);
    CHECK_EQ(RunCli({"repo", "add", repoDir, "--yes", "--fingerprint", fp, "--quiet"}), kExitOk);
    CHECK_EQ(RunCli({"repo", "add", repoDir, "--yes", "--fingerprint", fp, "--quiet"}), kExitUsage);  // exists
    CHECK_EQ(RunCli({"repo", "list"}), kExitOk);
    CHECK_EQ(RunCli({"search", "portable"}), kExitOk);
    CHECK_EQ(RunCli({"search", "no-such-thing-xyz"}), kExitNotFound);
    CHECK_EQ(RunCli({"info", "test.portable"}), kExitOk);

    // Dry run changes nothing.
    std::string zipBytes = ReadAll(sgtest::DataPath("good.zip"));
    repo.SeedCache("1.0", zipBytes);
    CHECK_EQ(RunCli({"install", "Test.Portable", "--user", "--dry-run"}), kExitOk);
    std::string appDir = JoinPath(GetAppPaths().userAppsDir, "Test.Portable");
    CHECK(!DirExists(appDir));

    // Tampered cached file: must be detected, deleted and never installed
    // (the re-download then fails because example.invalid does not resolve).
    repo.SeedCache("1.0", zipBytes + "tampered");
    int tamperCode = RunCli({"install", "Test.Portable", "--user", "--yes", "--quiet"});
    CHECK(tamperCode == kExitNetwork || tamperCode == kExitIntegrity);
    CHECK(!DirExists(appDir));

    // Real install from the verified cache.
    repo.SeedCache("1.0", zipBytes);
    CHECK_EQ(RunCli({"install", "Test.Portable", "--user", "--yes", "--quiet"}), kExitOk);
    CHECK(FileExists(JoinPath(appDir, "app\\tool.exe")));
    CHECK(FileExists(JoinPath(appDir, "app\\readme \xC3\xA9\xE6\x97\xA5.txt")));
    CHECK_EQ(RunCli({"list", "--json"}), kExitOk);
    CHECK_EQ(RunCli({"install", "Test.Portable", "--user", "--yes", "--quiet"}), kExitOk);  // already installed
    {
        Database db;
        db.Open(JoinPath(GetAppPaths().dataDir, "sevenget.db"));
        InstalledRecord r;
        CHECK(db.GetInstalled("Test.Portable", "user", r));
        CHECK_EQ(r.version, std::string("1.0"));
        CHECK(r.files.size() == 3);
    }

    // A user-created file inside the app directory survives the upgrade.
    WriteFileAtomic(JoinPath(appDir, "app\\user-settings.ini"), "mine");
    repo.Publish(2, "1.1", repo.zipSha);
    CHECK_EQ(RunCli({"update", "--quiet"}), kExitOk);
    CHECK_EQ(RunCli({"outdated"}), kExitOk);
    repo.SeedCache("1.1", zipBytes);
    CHECK_EQ(RunCli({"upgrade", "Test.Portable", "--dry-run"}), kExitOk);
    CHECK_EQ(RunCli({"upgrade", "--all", "--yes", "--quiet"}), kExitOk);
    CHECK(FileExists(JoinPath(appDir, "app\\user-settings.ini")));
    CHECK(FileExists(JoinPath(appDir, "app\\tool.exe")));
    {
        Database db;
        db.Open(JoinPath(GetAppPaths().dataDir, "sevenget.db"));
        InstalledRecord r;
        CHECK(db.GetInstalled("Test.Portable", "user", r) && r.version == "1.1");
    }
    CHECK_EQ(RunCli({"upgrade", "Test.Portable", "--yes", "--quiet"}), kExitOk);  // up to date

    // Rollback attack: the server goes back to sequence 1.
    repo.Publish(1, "1.0", repo.zipSha);
    CHECK_EQ(RunCli({"update", "--quiet"}), kExitTrust);
    // Key substitution attack: metadata re-signed by another key.
    LocalRepo attacker;
    attacker.Init(sgtest::TempDir("attacker"));
    attacker.dir = repoDir;
    attacker.Publish(3, "6.6.6", repo.zipSha);
    CHECK_EQ(RunCli({"update", "--quiet"}), kExitTrust);
    repo.Publish(4, "1.1", repo.zipSha);
    CHECK_EQ(RunCli({"update", "--quiet"}), kExitOk);

    // Concurrent operation is refused while the lock is held.
    {
        InstanceLock lock;
        CHECK(lock.Acquire(JoinPath(GetAppPaths().dataDir, "sevenget.lock")));
        CHECK_EQ(RunCli({"uninstall", "Test.Portable", "--yes", "--quiet"}), kExitBusy);
    }

    // Locked file: uninstall refuses and keeps the record.
    {
        HANDLE h = CreateFileW(Widen(JoinPath(appDir, "app\\tool.exe")).c_str(), GENERIC_READ, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        CHECK_EQ(RunCli({"uninstall", "Test.Portable", "--yes", "--quiet"}), kExitInstallerFailed);
        CloseHandle(h);
        CHECK(FileExists(JoinPath(appDir, "app\\tool.exe")));
    }
    CHECK_EQ(RunCli({"uninstall", "Test.Portable", "--yes", "--quiet"}), kExitOk);
    CHECK(!FileExists(JoinPath(appDir, "app\\tool.exe")));
    CHECK(FileExists(JoinPath(appDir, "app\\user-settings.ini")));  // not owned by SevenGet
    {
        Database db;
        db.Open(JoinPath(GetAppPaths().dataDir, "sevenget.db"));
        CHECK(db.FindInstalled("Test.Portable").empty());
        bool sawUpgrade = false, sawFailed = false;
        for (const auto& t : db.History(50)) {
            if (t.action == "upgrade" && t.state == "succeeded") sawUpgrade = true;
            if (t.state == "failed") sawFailed = true;
        }
        CHECK(sawUpgrade && sawFailed);
    }
    CHECK_EQ(RunCli({"history"}), kExitOk);
    CHECK_EQ(RunCli({"clean", "--quiet"}), kExitOk);
    CHECK_EQ(RunCli({"repo", "remove", "local-test", "--yes"}), kExitOk);
}
