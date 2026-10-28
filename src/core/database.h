// SevenGet - local state database (SQLite, statically linked).
//
// Durability: WAL journal with synchronous=FULL, every multi-row change inside
// a transaction. After each successful mutation a JSON snapshot of the
// installed-package records and repository trust state is written atomically
// next to the database so that `sevenget doctor --repair` can rebuild a
// corrupted database without losing ownership information.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

struct sqlite3;

namespace sg {

struct RepoRecord {
    std::string name;
    std::string url;           // https base URL or absolute local directory
    std::string publicKey;     // "sevenget-pubkey-v1 ecdsa-p256 <hex>"
    std::string fingerprint;   // lowercase hex
    int64_t priority = 0;      // lower = preferred
    bool enabled = true;
    int64_t sequence = 0;      // highest accepted metadata sequence (rollback protection)
    int64_t expires = 0;       // expiry of the accepted metadata (unix seconds)
    std::string indexSha256;   // digest of the accepted index.json
    int64_t updatedAt = 0;
    int64_t addedAt = 0;
};

struct InstalledRecord {
    std::string packageId;
    std::string name;          // display name at install time
    std::string scope;         // "user" | "machine"
    std::string version;
    std::string arch;
    std::string installerType; // exe | msi | zip
    std::string repository;
    std::string installLocation;
    int64_t installedAt = 0;
    int64_t updatedAt = 0;
    Json uninstall;            // backend-specific ownership data (see install/backend.h)
    std::string installerSha256;
    bool dependency = false;
    std::vector<std::string> files;  // zip: files owned by the package
};

struct TransactionRecord {
    int64_t id = 0;
    std::string action;  // install | upgrade | uninstall
    std::string packageId, fromVersion, toVersion, scope;
    std::string state;   // started | succeeded | failed | cancelled | interrupted | reboot-required
    int64_t startedAt = 0, finishedAt = 0;
    std::string message;
};

class Database {
public:
    Database() = default;
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Throws sg::Error(kExitDatabase) on failure (including corruption).
    void Open(const std::string& path, bool readOnly = false);
    void Close();
    bool IsOpen() const { return db_ != nullptr; }
    const std::string& path() const { return path_; }

    // Runs PRAGMA integrity_check; returns false and fills problems on corruption.
    bool IntegrityCheck(std::vector<std::string>& problems);

    void Begin();
    void Commit();
    void Rollback();

    // Repositories
    std::vector<RepoRecord> ListRepos();
    bool GetRepo(const std::string& name, RepoRecord& out);
    void PutRepo(const RepoRecord& r);
    bool RemoveRepo(const std::string& name);

    // Installed packages
    std::vector<InstalledRecord> ListInstalled();
    bool GetInstalled(const std::string& id, const std::string& scope, InstalledRecord& out);
    std::vector<InstalledRecord> FindInstalled(const std::string& id);  // any scope
    void PutInstalled(const InstalledRecord& r);  // replaces record and file list
    void RemoveInstalled(const std::string& id, const std::string& scope);

    // Transaction journal
    int64_t StartTransaction(const TransactionRecord& t);
    void FinishTransaction(int64_t id, const std::string& state, const std::string& message);
    // Marks transactions left in 'started' state by a crashed process as 'interrupted'.
    std::vector<TransactionRecord> RecoverInterrupted();
    std::vector<TransactionRecord> History(int limit);

    // Snapshot for disaster recovery.
    Json ExportSnapshot();
    void ImportSnapshot(const Json& snap);
    // Writes the snapshot file atomically; failures are logged, not fatal.
    void WriteSnapshotFile(const std::string& path);

    void Exec(const std::string& sql);

private:
    void Migrate();
    [[noreturn]] void Fail(const std::string& what);

    sqlite3* db_ = nullptr;
    std::string path_;
    int txDepth_ = 0;
};

}  // namespace sg
