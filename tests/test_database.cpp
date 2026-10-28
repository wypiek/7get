#include "core/database.h"
#include "platform/winutil.h"
#include "test.h"
#include "util/error.h"
#include "util/strings.h"

using namespace sg;

namespace {
InstalledRecord Sample(const std::string& id, const std::string& scope) {
    InstalledRecord r;
    r.packageId = id;
    r.name = "Sample \xC3\xA9";
    r.scope = scope;
    r.version = "1.0";
    r.arch = "x64";
    r.installerType = "zip";
    r.repository = "test";
    r.installLocation = "C:\\Users\\T\xC3\xA9st\\AppData\\Local\\SevenGet\\apps\\" + id;
    r.installedAt = 100;
    r.updatedAt = 200;
    r.uninstall = Json::Object();
    r.uninstall.Set("strategy", "files");
    r.uninstall.Set("root", r.installLocation);
    r.installerSha256 = std::string(64, 'a');
    r.files = {"tool.exe", "sub\\cfg.ini"};
    return r;
}
}  // namespace

TEST(database_installed_records_roundtrip) {
    std::string dir = sgtest::TempDir("db1 \xE6\x97\xA5");
    Database db;
    db.Open(JoinPath(dir, "s.db"));
    db.PutInstalled(Sample("A.App", "user"));
    db.PutInstalled(Sample("A.App", "machine"));
    InstalledRecord r;
    CHECK(db.GetInstalled("a.app", "user", r));  // ids are case-insensitive
    CHECK_EQ(r.name, std::string("Sample \xC3\xA9"));
    CHECK(r.files.size() == 2);
    CHECK_EQ(r.uninstall.Find("strategy")->AsString(), std::string("files"));
    CHECK(db.FindInstalled("A.App").size() == 2);
    db.RemoveInstalled("A.App", "user");
    CHECK(db.FindInstalled("A.App").size() == 1);
    CHECK(db.ListInstalled().size() == 1);
    std::vector<std::string> problems;
    CHECK(db.IntegrityCheck(problems));
}

TEST(database_rejects_invalid_records) {
    std::string dir = sgtest::TempDir("db2");
    Database db;
    db.Open(JoinPath(dir, "s.db"));
    InstalledRecord bad = Sample("X", "everyone");  // CHECK constraint on scope
    bool threw = false;
    try {
        db.PutInstalled(bad);
    } catch (const Error& e) {
        threw = e.code() == kExitDatabase;
    }
    CHECK(threw);
    CHECK(db.ListInstalled().empty());  // rolled back, nothing half-written
}

TEST(database_transaction_journal_and_crash_recovery) {
    std::string dir = sgtest::TempDir("db3");
    std::string path = JoinPath(dir, "s.db");
    {
        Database db;
        db.Open(path);
        TransactionRecord t;
        t.action = "install";
        t.packageId = "A";
        t.toVersion = "1.0";
        t.scope = "user";
        int64_t id = db.StartTransaction(t);
        db.FinishTransaction(id, "failed", "installer exit code 1603");
        db.StartTransaction(t);  // simulate crash: never finished
    }
    Database db;
    db.Open(path);
    auto rec = db.RecoverInterrupted();
    CHECK(rec.size() == 1);
    auto hist = db.History(10);
    CHECK(hist.size() == 2);
    CHECK_EQ(hist[0].state, std::string("interrupted"));
    CHECK_EQ(hist[1].state, std::string("failed"));
    CHECK(db.RecoverInterrupted().empty());
}

TEST(database_corruption_detected_and_snapshot_restores) {
    std::string dir = sgtest::TempDir("db4");
    std::string path = JoinPath(dir, "s.db");
    std::string snapPath = JoinPath(dir, "snap.json");
    {
        Database db;
        db.Open(path);
        db.PutInstalled(Sample("Keep.Me", "user"));
        RepoRecord repo;
        repo.name = "main";
        repo.url = "https://example.invalid/repo";
        repo.publicKey = "k";
        repo.fingerprint = std::string(64, 'b');
        repo.sequence = 42;
        repo.addedAt = 1;
        db.PutRepo(repo);
        db.WriteSnapshotFile(snapPath);
    }
    // Overwrite the database with garbage (simulated disk corruption).
    CHECK(WriteFileAtomic(path, std::string(8192, 'X')));
    DeleteFileUtf8(path + "-wal");
    DeleteFileUtf8(path + "-shm");
    bool detected = false;
    try {
        Database db;
        db.Open(path);
    } catch (const Error& e) {
        detected = e.code() == kExitDatabase;
    }
    CHECK(detected);
    // Rebuild from the snapshot; rollback watermark (sequence) survives.
    DeleteFileUtf8(path);
    Database db;
    db.Open(path);
    std::string text;
    CHECK(ReadFileBytes(snapPath, text));
    db.ImportSnapshot(ParseJson(text).value);
    InstalledRecord r;
    CHECK(db.GetInstalled("Keep.Me", "user", r));
    CHECK(r.files.size() == 2);
    RepoRecord repo;
    CHECK(db.GetRepo("main", repo) && repo.sequence == 42);
}

TEST(database_nested_transaction_rollback) {
    std::string dir = sgtest::TempDir("db5");
    Database db;
    db.Open(JoinPath(dir, "s.db"));
    db.Begin();
    db.PutInstalled(Sample("T1", "user"));
    db.Rollback();
    CHECK(db.ListInstalled().empty());
}
