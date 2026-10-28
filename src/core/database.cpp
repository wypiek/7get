#include "core/database.h"

#include <windows.h>

#include "platform/winutil.h"
#include "sqlite3.h"
#include "util/error.h"
#include "util/strings.h"

namespace sg {

namespace {

const int kSchemaVersion = 1;

const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repositories(
  name TEXT PRIMARY KEY COLLATE NOCASE,
  url TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  sequence INTEGER NOT NULL DEFAULT 0,
  expires INTEGER NOT NULL DEFAULT 0,
  index_sha256 TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0,
  added_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS installed(
  package_id TEXT NOT NULL COLLATE NOCASE,
  scope TEXT NOT NULL CHECK(scope IN ('user','machine')),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  arch TEXT NOT NULL,
  installer_type TEXT NOT NULL CHECK(installer_type IN ('exe','msi','zip')),
  repository TEXT NOT NULL,
  install_location TEXT NOT NULL DEFAULT '',
  installed_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  uninstall TEXT NOT NULL,
  installer_sha256 TEXT NOT NULL,
  dependency INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(package_id, scope));
CREATE TABLE IF NOT EXISTS installed_files(
  package_id TEXT NOT NULL COLLATE NOCASE,
  scope TEXT NOT NULL,
  path TEXT NOT NULL,
  PRIMARY KEY(package_id, scope, path));
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  package_id TEXT NOT NULL,
  from_version TEXT NOT NULL DEFAULT '',
  to_version TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT '',
  pid INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS transactions_state ON transactions(state);
)SQL";

class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &s_, nullptr) != SQLITE_OK)
            throw Error(kExitDatabase, std::string("database error: ") + sqlite3_errmsg(db));
    }
    ~Stmt() { sqlite3_finalize(s_); }
    Stmt& Bind(int i, const std::string& v) {
        sqlite3_bind_text(s_, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& Bind(int i, int64_t v) {
        sqlite3_bind_int64(s_, i, v);
        return *this;
    }
    bool Step() {
        int rc = sqlite3_step(s_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw Error(kExitDatabase, std::string("database error: ") + sqlite3_errmsg(db_),
                    rc == SQLITE_CORRUPT || rc == SQLITE_NOTADB ? "run 'sevenget doctor --repair'" : "");
    }
    std::string Text(int c) {
        const unsigned char* t = sqlite3_column_text(s_, c);
        return t ? std::string(reinterpret_cast<const char*>(t), static_cast<size_t>(sqlite3_column_bytes(s_, c))) : "";
    }
    int64_t Int(int c) { return sqlite3_column_int64(s_, c); }

private:
    sqlite3* db_;
    sqlite3_stmt* s_ = nullptr;
};

RepoRecord ReadRepo(Stmt& s) {
    RepoRecord r;
    r.name = s.Text(0);
    r.url = s.Text(1);
    r.publicKey = s.Text(2);
    r.fingerprint = s.Text(3);
    r.priority = s.Int(4);
    r.enabled = s.Int(5) != 0;
    r.sequence = s.Int(6);
    r.expires = s.Int(7);
    r.indexSha256 = s.Text(8);
    r.updatedAt = s.Int(9);
    r.addedAt = s.Int(10);
    return r;
}

const char* kRepoCols =
    "name,url,public_key,fingerprint,priority,enabled,sequence,expires,index_sha256,updated_at,added_at";
const char* kInstCols =
    "package_id,scope,name,version,arch,installer_type,repository,install_location,installed_at,updated_at,"
    "uninstall,installer_sha256,dependency";

InstalledRecord ReadInstalled(Stmt& s) {
    InstalledRecord r;
    r.packageId = s.Text(0);
    r.scope = s.Text(1);
    r.name = s.Text(2);
    r.version = s.Text(3);
    r.arch = s.Text(4);
    r.installerType = s.Text(5);
    r.repository = s.Text(6);
    r.installLocation = s.Text(7);
    r.installedAt = s.Int(8);
    r.updatedAt = s.Int(9);
    auto pr = ParseJson(s.Text(10));
    r.uninstall = pr.ok ? pr.value : Json::Object();
    r.installerSha256 = s.Text(11);
    r.dependency = s.Int(12) != 0;
    return r;
}

TransactionRecord ReadTx(Stmt& s) {
    TransactionRecord t;
    t.id = s.Int(0);
    t.action = s.Text(1);
    t.packageId = s.Text(2);
    t.fromVersion = s.Text(3);
    t.toVersion = s.Text(4);
    t.scope = s.Text(5);
    t.state = s.Text(6);
    t.startedAt = s.Int(7);
    t.finishedAt = s.Int(8);
    t.message = s.Text(9);
    return t;
}

}  // namespace

Database::~Database() { Close(); }

void Database::Fail(const std::string& what) {
    std::string msg = what + ": " + (db_ ? sqlite3_errmsg(db_) : "unknown error");
    int ext = db_ ? sqlite3_extended_errcode(db_) : 0;
    bool corrupt = (ext & 0xFF) == SQLITE_CORRUPT || (ext & 0xFF) == SQLITE_NOTADB;
    throw Error(kExitDatabase, msg, corrupt ? "the database appears corrupted; run 'sevenget doctor --repair'" : "");
}

void Database::Open(const std::string& path, bool readOnly) {
    Close();
    path_ = path;
    if (!readOnly) CreateDirectories(ParentPath(path));
    int flags = readOnly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    flags |= SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "out of memory";
        Close();
        throw Error(kExitDatabase, "cannot open database " + path + ": " + err);
    }
    sqlite3_busy_timeout(db_, 5000);
    sqlite3_extended_result_codes(db_, 1);
    try {
        // Touch the schema to detect "file is not a database" early.
        Exec("SELECT count(*) FROM sqlite_master;");
        if (!readOnly) {
            Exec("PRAGMA journal_mode=WAL;");
            Exec("PRAGMA synchronous=FULL;");
            Exec("PRAGMA foreign_keys=ON;");
            Migrate();
        }
    } catch (...) {
        Close();
        throw;
    }
}

void Database::Close() {
    if (db_) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
    txDepth_ = 0;
}

void Database::Exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string m = err ? err : "unknown";
        sqlite3_free(err);
        Fail("database error (" + m + ")");
    }
}

void Database::Migrate() {
    Begin();
    try {
        Exec(kSchema);
        Stmt s(db_, "SELECT value FROM meta WHERE key='schema_version'");
        int64_t v = 0;
        if (s.Step()) ParseInt64(s.Text(0), v);
        if (v > kSchemaVersion)
            throw Error(kExitDatabase, "database was created by a newer SevenGet (schema " + std::to_string(v) + ")");
        Stmt u(db_, "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)");
        u.Bind(1, std::to_string(kSchemaVersion)).Step();
        Commit();
    } catch (...) {
        Rollback();
        throw;
    }
}

bool Database::IntegrityCheck(std::vector<std::string>& problems) {
    Stmt s(db_, "PRAGMA integrity_check");
    while (s.Step()) {
        std::string t = s.Text(0);
        if (t != "ok") problems.push_back(t);
    }
    return problems.empty();
}

void Database::Begin() {
    if (txDepth_++ == 0) Exec("BEGIN IMMEDIATE;");
}

void Database::Commit() {
    if (txDepth_ == 0) return;
    if (--txDepth_ == 0) Exec("COMMIT;");
}

void Database::Rollback() {
    if (txDepth_ == 0) return;
    txDepth_ = 0;
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
}

std::vector<RepoRecord> Database::ListRepos() {
    std::vector<RepoRecord> out;
    Stmt s(db_, (std::string("SELECT ") + kRepoCols + " FROM repositories ORDER BY priority, name").c_str());
    while (s.Step()) out.push_back(ReadRepo(s));
    return out;
}

bool Database::GetRepo(const std::string& name, RepoRecord& out) {
    Stmt s(db_, (std::string("SELECT ") + kRepoCols + " FROM repositories WHERE name=?").c_str());
    s.Bind(1, name);
    if (!s.Step()) return false;
    out = ReadRepo(s);
    return true;
}

void Database::PutRepo(const RepoRecord& r) {
    Stmt s(db_, (std::string("INSERT OR REPLACE INTO repositories(") + kRepoCols +
                 ") VALUES(?,?,?,?,?,?,?,?,?,?,?)").c_str());
    s.Bind(1, r.name).Bind(2, r.url).Bind(3, r.publicKey).Bind(4, r.fingerprint).Bind(5, r.priority)
        .Bind(6, static_cast<int64_t>(r.enabled ? 1 : 0)).Bind(7, r.sequence).Bind(8, r.expires)
        .Bind(9, r.indexSha256).Bind(10, r.updatedAt).Bind(11, r.addedAt);
    s.Step();
}

bool Database::RemoveRepo(const std::string& name) {
    Stmt s(db_, "DELETE FROM repositories WHERE name=?");
    s.Bind(1, name).Step();
    return sqlite3_changes(db_) > 0;
}

std::vector<InstalledRecord> Database::ListInstalled() {
    std::vector<InstalledRecord> out;
    {
        Stmt s(db_, (std::string("SELECT ") + kInstCols + " FROM installed ORDER BY package_id, scope").c_str());
        while (s.Step()) out.push_back(ReadInstalled(s));
    }
    for (auto& r : out) {
        Stmt f(db_, "SELECT path FROM installed_files WHERE package_id=? AND scope=? ORDER BY path");
        f.Bind(1, r.packageId).Bind(2, r.scope);
        while (f.Step()) r.files.push_back(f.Text(0));
    }
    return out;
}

bool Database::GetInstalled(const std::string& id, const std::string& scope, InstalledRecord& out) {
    Stmt s(db_, (std::string("SELECT ") + kInstCols + " FROM installed WHERE package_id=? AND scope=?").c_str());
    s.Bind(1, id).Bind(2, scope);
    if (!s.Step()) return false;
    out = ReadInstalled(s);
    Stmt f(db_, "SELECT path FROM installed_files WHERE package_id=? AND scope=? ORDER BY path");
    f.Bind(1, out.packageId).Bind(2, out.scope);
    while (f.Step()) out.files.push_back(f.Text(0));
    return true;
}

std::vector<InstalledRecord> Database::FindInstalled(const std::string& id) {
    std::vector<InstalledRecord> out;
    for (const char* scope : {"user", "machine"}) {
        InstalledRecord r;
        if (GetInstalled(id, scope, r)) out.push_back(r);
    }
    return out;
}

void Database::PutInstalled(const InstalledRecord& r) {
    Begin();
    try {
        Stmt s(db_, (std::string("INSERT OR REPLACE INTO installed(") + kInstCols +
                     ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)").c_str());
        s.Bind(1, r.packageId).Bind(2, r.scope).Bind(3, r.name).Bind(4, r.version).Bind(5, r.arch)
            .Bind(6, r.installerType).Bind(7, r.repository).Bind(8, r.installLocation).Bind(9, r.installedAt)
            .Bind(10, r.updatedAt).Bind(11, r.uninstall.Dump()).Bind(12, r.installerSha256)
            .Bind(13, static_cast<int64_t>(r.dependency ? 1 : 0));
        s.Step();
        Stmt d(db_, "DELETE FROM installed_files WHERE package_id=? AND scope=?");
        d.Bind(1, r.packageId).Bind(2, r.scope).Step();
        for (const auto& f : r.files) {
            Stmt i(db_, "INSERT OR IGNORE INTO installed_files(package_id,scope,path) VALUES(?,?,?)");
            i.Bind(1, r.packageId).Bind(2, r.scope).Bind(3, f).Step();
        }
        Commit();
    } catch (...) {
        Rollback();
        throw;
    }
}

void Database::RemoveInstalled(const std::string& id, const std::string& scope) {
    Begin();
    try {
        Stmt d(db_, "DELETE FROM installed_files WHERE package_id=? AND scope=?");
        d.Bind(1, id).Bind(2, scope).Step();
        Stmt s(db_, "DELETE FROM installed WHERE package_id=? AND scope=?");
        s.Bind(1, id).Bind(2, scope).Step();
        Commit();
    } catch (...) {
        Rollback();
        throw;
    }
}

int64_t Database::StartTransaction(const TransactionRecord& t) {
    Stmt s(db_,
           "INSERT INTO transactions(action,package_id,from_version,to_version,scope,state,started_at,pid) "
           "VALUES(?,?,?,?,?,'started',?,?)");
    s.Bind(1, t.action).Bind(2, t.packageId).Bind(3, t.fromVersion).Bind(4, t.toVersion).Bind(5, t.scope)
        .Bind(6, NowUnix()).Bind(7, static_cast<int64_t>(GetCurrentProcessId()));
    s.Step();
    return sqlite3_last_insert_rowid(db_);
}

void Database::FinishTransaction(int64_t id, const std::string& state, const std::string& message) {
    Stmt s(db_, "UPDATE transactions SET state=?, finished_at=?, message=? WHERE id=?");
    s.Bind(1, state).Bind(2, NowUnix()).Bind(3, message).Bind(4, id).Step();
}

std::vector<TransactionRecord> Database::RecoverInterrupted() {
    std::vector<TransactionRecord> out;
    {
        // Only one SevenGet process mutates state at a time (InstanceLock), so
        // any 'started' row seen while holding the lock belongs to a dead process.
        Stmt s(db_, "SELECT id,action,package_id,from_version,to_version,scope,state,started_at,finished_at,message "
                    "FROM transactions WHERE state='started'");
        while (s.Step()) out.push_back(ReadTx(s));
    }
    for (auto& t : out) {
        FinishTransaction(t.id, "interrupted", "process ended before the operation completed");
        t.state = "interrupted";
    }
    return out;
}

std::vector<TransactionRecord> Database::History(int limit) {
    std::vector<TransactionRecord> out;
    Stmt s(db_, "SELECT id,action,package_id,from_version,to_version,scope,state,started_at,finished_at,message "
                "FROM transactions ORDER BY id DESC LIMIT ?");
    s.Bind(1, static_cast<int64_t>(limit));
    while (s.Step()) out.push_back(ReadTx(s));
    return out;
}

Json Database::ExportSnapshot() {
    Json snap = Json::Object();
    snap.Set("format", "sevenget-snapshot-v1");
    snap.Set("written", FormatUtc(NowUnix()));
    Json repos = Json::Array();
    for (const auto& r : ListRepos()) {
        Json j = Json::Object();
        j.Set("name", r.name);
        j.Set("url", r.url);
        j.Set("publicKey", r.publicKey);
        j.Set("fingerprint", r.fingerprint);
        j.Set("priority", r.priority);
        j.Set("enabled", r.enabled);
        j.Set("sequence", r.sequence);
        j.Set("expires", r.expires);
        j.Set("indexSha256", r.indexSha256);
        j.Set("updatedAt", r.updatedAt);
        j.Set("addedAt", r.addedAt);
        repos.Push(j);
    }
    snap.Set("repositories", repos);
    Json inst = Json::Array();
    for (const auto& r : ListInstalled()) {
        Json j = Json::Object();
        j.Set("packageId", r.packageId);
        j.Set("name", r.name);
        j.Set("scope", r.scope);
        j.Set("version", r.version);
        j.Set("arch", r.arch);
        j.Set("installerType", r.installerType);
        j.Set("repository", r.repository);
        j.Set("installLocation", r.installLocation);
        j.Set("installedAt", r.installedAt);
        j.Set("updatedAt", r.updatedAt);
        j.Set("uninstall", r.uninstall);
        j.Set("installerSha256", r.installerSha256);
        j.Set("dependency", r.dependency);
        Json files = Json::Array();
        for (const auto& f : r.files) files.Push(f);
        j.Set("files", files);
        inst.Push(j);
    }
    snap.Set("installed", inst);
    return snap;
}

void Database::ImportSnapshot(const Json& snap) {
    const Json* fmt = snap.Find("format");
    if (!fmt || !fmt->IsString() || fmt->AsString() != "sevenget-snapshot-v1")
        throw Error(kExitDatabase, "snapshot has an unknown format");
    auto str = [](const Json& o, const char* k) {
        const Json* v = o.Find(k);
        return v && v->IsString() ? v->AsString() : std::string();
    };
    auto num = [](const Json& o, const char* k) {
        const Json* v = o.Find(k);
        return v && v->IsInteger() ? v->AsInt() : int64_t(0);
    };
    auto flag = [](const Json& o, const char* k) {
        const Json* v = o.Find(k);
        return v && v->IsBool() && v->AsBool();
    };
    Begin();
    try {
        if (const Json* repos = snap.Find("repositories"))
            for (const auto& j : repos->Items()) {
                RepoRecord r;
                r.name = str(j, "name");
                r.url = str(j, "url");
                r.publicKey = str(j, "publicKey");
                r.fingerprint = str(j, "fingerprint");
                r.priority = num(j, "priority");
                r.enabled = flag(j, "enabled");
                r.sequence = num(j, "sequence");
                r.expires = num(j, "expires");
                r.indexSha256 = str(j, "indexSha256");
                r.updatedAt = num(j, "updatedAt");
                r.addedAt = num(j, "addedAt");
                if (!r.name.empty()) PutRepo(r);
            }
        if (const Json* inst = snap.Find("installed"))
            for (const auto& j : inst->Items()) {
                InstalledRecord r;
                r.packageId = str(j, "packageId");
                r.name = str(j, "name");
                r.scope = str(j, "scope");
                r.version = str(j, "version");
                r.arch = str(j, "arch");
                r.installerType = str(j, "installerType");
                r.repository = str(j, "repository");
                r.installLocation = str(j, "installLocation");
                r.installedAt = num(j, "installedAt");
                r.updatedAt = num(j, "updatedAt");
                if (const Json* u = j.Find("uninstall")) r.uninstall = *u;
                r.installerSha256 = str(j, "installerSha256");
                r.dependency = flag(j, "dependency");
                if (const Json* files = j.Find("files"))
                    for (const auto& f : files->Items())
                        if (f.IsString()) r.files.push_back(f.AsString());
                if (!r.packageId.empty()) PutInstalled(r);
            }
        Commit();
    } catch (...) {
        Rollback();
        throw;
    }
}

void Database::WriteSnapshotFile(const std::string& path) {
    try {
        WriteFileAtomic(path, ExportSnapshot().Dump(true));
    } catch (...) {
    }
}

}  // namespace sg
