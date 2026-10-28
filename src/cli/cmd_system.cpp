// SevenGet - repository, configuration and maintenance commands.
#include <windows.h>

#include "cli/context.h"
#include "platform/authenticode.h"
#include "platform/console.h"
#include "platform/crypto.h"
#include "platform/http.h"
#include "util/error.h"
#include "util/log.h"
#include "util/strings.h"

namespace sg {

namespace {

std::string NormalizeRepoUrl(const std::string& url) {
    std::string u = Trim(url);
    if (IsLocalRepoPath(u)) {
        u = GetFullPath(u);
        while (u.size() > 3 && (u.back() == '\\' || u.back() == '/')) u.pop_back();
        return u;
    }
    if (StartsWith(ToLowerAscii(u), "http://"))
        throw Error(kExitUsage, "plain http:// repositories are not allowed; use https://");
    if (!IsHttpsUrl(u))
        throw Error(kExitUsage, "repository location must be an https:// URL or an absolute directory path: " + url);
    while (EndsWith(u, "/")) u.pop_back();
    return u;
}

std::string CompactFingerprint(const std::string& s) {
    std::string out;
    for (char c : s)
        if (c != ' ' && c != ':' && c != '-') out += c;
    return ToLowerAscii(out);
}

int RepoList(CommandContext& c) {
    c.OpenDatabase();
    Table t({"NAME", "LOCATION", "KEY FINGERPRINT", "SEQUENCE", "EXPIRES (UTC)", "STATUS"});
    Json arr = Json::Array();
    int64_t now = NowUnix();
    for (const auto& r : c.db.ListRepos()) {
        std::string status = !r.enabled ? "disabled" : r.expires && now > r.expires ? "EXPIRED" : "ok";
        PublicKey k;
        std::string err;
        std::string fp = ParsePublicKey(r.publicKey, k, err) ? k.FingerprintDisplay() : "invalid";
        t.AddRow({r.name, r.url, fp.substr(0, 19) + "...", std::to_string(r.sequence),
                  r.expires ? FormatUtc(r.expires) : "-", status},
                 status == "ok" ? Color::Default : Color::Yellow);
        Json j = Json::Object();
        j.Set("name", r.name);
        j.Set("url", r.url);
        j.Set("fingerprint", r.fingerprint);
        j.Set("sequence", r.sequence);
        j.Set("expires", r.expires ? Json(FormatUtc(r.expires)) : Json());
        j.Set("updated", r.updatedAt ? Json(FormatUtc(r.updatedAt)) : Json());
        j.Set("priority", r.priority);
        j.Set("status", status);
        arr.Push(j);
    }
    c.out.Set("repositories", arr);
    if (t.Empty()) Console::OutLine("No repositories configured. Add one with 'sevenget repo add <url>'.");
    else t.Print();
    return kExitOk;
}

int RepoAdd(CommandContext& c) {
    if (c.args.positional.size() != 2) throw Error(kExitUsage, "usage: sevenget repo add <url> [--name N] [--fingerprint FP]");
    std::string url = NormalizeRepoUrl(c.args.positional[1]);
    if (c.args.yes && c.args.fingerprint.empty())
        throw Error(kExitUsage, "--yes requires --fingerprint when adding a repository",
                    "SevenGet never trusts a repository key silently; pass the fingerprint published by the operator");
    c.AcquireLock();

    std::string keyText;
    if (!c.args.keyFile.empty()) {
        if (!ReadFileBytes(c.args.keyFile, keyText, 64 * 1024))
            throw Error(kExitNotFound, "cannot read key file " + c.args.keyFile);
    } else {
        Console::Step("Fetching repository key");
        int code = 0;
        std::string err;
        if (!c.repos->FetchPublicKey(url, keyText, code, err)) {
            Console::StepResult("FAILED", Color::Red);
            throw Error(code, "could not fetch key.pub from the repository: " + err);
        }
        Console::StepResult("OK", Color::Green);
    }
    PublicKey key;
    std::string err;
    if (!ParsePublicKey(keyText, key, err)) throw Error(kExitTrust, "invalid repository key: " + err);

    Console::Step("Fetching and verifying signed metadata");
    IndexCheck probe = c.repos->Probe(url, key);
    if (!probe.ok) {
        Console::StepResult("FAILED", Color::Red);
        throw Error(probe.code ? probe.code : kExitTrust, probe.error, probe.hint);
    }
    Console::StepResult("OK (" + std::to_string(probe.index.packages.size()) + " packages, sequence " +
                            std::to_string(probe.index.sequence) + ", expires " + FormatUtc(probe.index.expires) + ")",
                        Color::Green);
    std::string name = c.args.name.empty() ? probe.index.repository : c.args.name;
    if (!IsValidRepoName(name)) throw Error(kExitUsage, "invalid repository name '" + name + "'");
    if (!EqualsIgnoreCase(name, probe.index.repository))
        throw Error(kExitTrust, "repository calls itself '" + probe.index.repository + "', not '" + name + "'");
    RepoRecord existing;
    bool exists = c.db.GetRepo(name, existing);
    if (exists && !c.args.replace)
        throw Error(kExitUsage, "repository '" + name + "' already exists",
                    "use 'sevenget repo add <url> --replace' to re-enroll it (for example after a key rotation)");

    Console::OutLine();
    Console::OutLine("Repository:      " + name);
    Console::OutLine("Location:        " + url);
    Console::OutLine("Key fingerprint: " + key.FingerprintDisplay(), Color::White);
    if (exists && !EqualsIgnoreCase(existing.fingerprint, key.Fingerprint()))
        Console::Warn("this REPLACES the previously trusted key " + existing.fingerprint.substr(0, 16) + "...");
    c.out.Set("name", name);
    c.out.Set("url", url);
    c.out.Set("fingerprint", key.Fingerprint());

    if (!c.args.fingerprint.empty()) {
        if (CompactFingerprint(c.args.fingerprint) != key.Fingerprint())
            throw Error(kExitTrust, "the repository key fingerprint does not match --fingerprint",
                        "do not add this repository unless the operator confirms the new fingerprint");
        Console::OutLine("Fingerprint matches the value given with --fingerprint.", Color::Green);
    } else {
        Console::OutLine();
        Console::OutLine("Only continue if this fingerprint matches the one published by the repository operator");
        Console::OutLine("through a channel you trust. Anyone holding this key can publish software for you to install.");
        if (Console::Options().json || !Console::StdinIsConsole())
            throw Error(kExitUsage, "key confirmation requires an interactive console or --fingerprint");
        if (!Console::Confirm("Trust this key?")) throw Error(kExitCancelled, "repository not added");
    }
    c.repos->Enroll(name, url, key, probe, c.repos->probedIndex(), c.repos->probedSig());
    c.db.WriteSnapshotFile(JoinPath(GetAppPaths().dataDir, "installed-snapshot.json"));
    Log::Info("repository " + name + " enrolled from " + url + " key " + key.Fingerprint());
    for (const auto& w : probe.index.warnings) c.Warn(w);
    Console::OutLine("Repository '" + name + "' added.", Color::Green);
    return kExitOk;
}

int RepoRemove(CommandContext& c) {
    if (c.args.positional.size() != 2) throw Error(kExitUsage, "usage: sevenget repo remove <name>");
    std::string name = c.args.positional[1];
    c.AcquireLock();
    RepoRecord r;
    if (!c.db.GetRepo(name, r)) throw Error(kExitNotFound, "repository '" + name + "' is not configured");
    if (c.args.dryRun) {
        Console::OutLine("Dry run: would remove repository '" + r.name + "' and its trusted key.");
        return kExitOk;
    }
    if (!c.args.yes) {
        if (Console::Options().json || !Console::StdinIsConsole())
            throw Error(kExitUsage, "confirmation required; re-run with --yes");
        if (!Console::Confirm("Remove repository '" + r.name + "' and its trusted key?"))
            throw Error(kExitCancelled, "repository not removed");
    }
    c.db.RemoveRepo(r.name);
    RemoveTree(c.repos->CacheDir(r.name));
    c.db.WriteSnapshotFile(JoinPath(GetAppPaths().dataDir, "installed-snapshot.json"));
    Log::Info("repository " + r.name + " removed");
    Console::OutLine("Repository '" + r.name + "' removed. Packages installed from it remain installed and can still be uninstalled.");
    return kExitOk;
}

}  // namespace

int CmdRepo(CommandContext& c) {
    std::string sub = c.args.positional.empty() ? "list" : c.args.positional[0];
    if (sub == "list") return RepoList(c);
    if (sub == "add") return RepoAdd(c);
    if (sub == "remove" || sub == "rm") return RepoRemove(c);
    throw Error(kExitUsage, "unknown repo subcommand '" + sub + "' (use list, add or remove)");
}

int CmdUpdate(CommandContext& c) {
    if (!c.args.positional.empty()) throw Error(kExitUsage, "update takes no arguments");
    c.AcquireLock();
    auto repos = c.db.ListRepos();
    if (repos.empty()) throw Error(kExitNotFound, "no repositories configured", "add one with 'sevenget repo add <url>'");
    int worst = kExitOk;
    Json arr = Json::Array();
    for (const auto& r : repos) {
        if (!r.enabled) continue;
        Console::Step("Updating " + r.name);
        IndexCheck res = c.repos->Update(r);
        Json j = Json::Object();
        j.Set("name", r.name);
        j.Set("ok", res.ok);
        if (res.ok) {
            bool changed = res.index.sequence != r.sequence;
            Console::StepResult((changed ? "updated to sequence " + std::to_string(res.index.sequence)
                                         : std::string("up to date")) +
                                    " (" + std::to_string(res.index.packages.size()) + " packages, expires " +
                                    FormatUtc(res.index.expires) + ")",
                                Color::Green);
            j.Set("sequence", res.index.sequence);
            j.Set("changed", changed);
            j.Set("packages", static_cast<int64_t>(res.index.packages.size()));
            for (const auto& w : res.index.warnings) c.Warn(r.name + ": " + w);
            Log::Info("repository " + r.name + " sequence " + std::to_string(res.index.sequence));
        } else {
            Console::StepResult("FAILED", Color::Red);
            Console::Error(r.name + ": " + res.error);
            if (!res.hint.empty()) Console::Info("  " + res.hint);
            j.Set("error", res.error);
            Log::Error("repository " + r.name + " update failed: " + res.error);
            if (worst == kExitOk || res.code == kExitTrust) worst = res.code ? res.code : kExitError;
        }
        arr.Push(j);
    }
    c.out.Set("repositories", arr);
    c.db.WriteSnapshotFile(JoinPath(GetAppPaths().dataDir, "installed-snapshot.json"));
    return worst;
}

int CmdConfig(CommandContext& c) {
    std::string sub = c.args.positional.empty() ? "list" : c.args.positional[0];
    if (sub == "list") {
        if (c.args.positional.size() > 1) throw Error(kExitUsage, "usage: sevenget config list");
        Table t({"KEY", "VALUE", "DESCRIPTION"});
        Json obj = Json::Object();
        for (const auto& k : ConfigKeys()) {
            std::string v = c.config.Get(k.key);
            t.AddRow({k.key, (v.empty() ? "\"\"" : v) + (c.config.IsDefault(k.key) ? "" : " *"), k.description});
            obj.Set(k.key, v);
        }
        c.out.Set("config", obj);
        t.Print();
        Console::OutLine("(* = changed from default)  File: " + JoinPath(GetAppPaths().configDir, "config.json"), Color::Gray);
        return kExitOk;
    }
    if (sub == "get") {
        if (c.args.positional.size() != 2) throw Error(kExitUsage, "usage: sevenget config get <key>");
        const std::string& key = c.args.positional[1];
        if (!Config::IsKnownKey(key)) throw Error(kExitNotFound, "unknown configuration key '" + key + "'");
        c.out.Set("key", key);
        c.out.Set("value", c.config.Get(key));
        Console::OutLine(c.config.Get(key));
        return kExitOk;
    }
    if (sub == "set") {
        if (c.args.positional.size() != 3) throw Error(kExitUsage, "usage: sevenget config set <key> <value>");
        std::string err;
        if (!c.config.Set(c.args.positional[1], c.args.positional[2], err)) throw Error(kExitUsage, err);
        if (!c.config.Save(err)) throw Error(kExitError, err);
        c.out.Set("key", c.args.positional[1]);
        c.out.Set("value", c.config.Get(c.args.positional[1]));
        Console::OutLine(c.args.positional[1] + " = " + c.config.Get(c.args.positional[1]));
        return kExitOk;
    }
    throw Error(kExitUsage, "unknown config subcommand '" + sub + "' (use list, get or set)");
}

int CmdClean(CommandContext& c) {
    if (!c.args.positional.empty()) throw Error(kExitUsage, "clean takes no arguments (use --all)");
    c.AcquireLock();
    const AppPaths& p = GetAppPaths();
    std::vector<std::string> targets = {JoinPath(p.cacheDir, "downloads"), p.tempDir};
    if (c.args.all) targets.push_back(JoinPath(p.cacheDir, "repos"));
    uint64_t freed = 0;
    for (const auto& t : targets) {
        uint64_t sz = DirectorySize(t);
        if (c.args.dryRun) {
            freed += sz;
            continue;
        }
        if (RemoveTree(t)) freed += sz;
        else c.Warn("could not remove everything in " + t + " (files in use?)");
    }
    c.out.Set("freedBytes", static_cast<int64_t>(freed));
    Console::OutLine((c.args.dryRun ? "Would free " : "Freed ") + FormatBytes(freed) + ".");
    if (c.args.all && !c.args.dryRun) Console::OutLine("Run 'sevenget update' to download repository metadata again.");
    return kExitOk;
}

// ------------------------------------------------------------------ doctor

namespace {

struct Check {
    std::string name;
    std::string status;  // OK / WARN / FAIL / INFO
    std::string detail;
};

// ECDSA P-256 test vector produced with OpenSSL (independent implementation)
// so that doctor proves this system's CNG verifies real-world signatures.
const char kTestPub[] =
    "047fc62733e0e26f8a9ed6e1553e09f8c01f38c9eb76f1e57bb4d666b7cc9ef408337eacdc9f9fb3df8e576a40e37f3bd8f5ade3c00b"
    "dffe2cddd1280f35cec110";
const char kTestSig[] =
    "ad78637634eb49d7db0aa05adcf4ee8189780978a5d6a052c0e8674aad7060fda9985bc930b4e8574627a8f1fe4fd0468bf583a87c66c9"
    "4c5a5a0a1cd4b40262";
const char kTestMsg[] = "SevenGet CNG ECDSA P-256 self-test vector";

bool CheckWinHttpTlsRegistry(std::string& detail) {
    // KB3140245 introduced HKLM\...\Internet Settings\WinHttp\DefaultSecureProtocols.
    // 0x800 = TLS 1.2. SevenGet sets TLS 1.2 per session, which works once the
    // update is installed, but other software on the system benefits too.
    uint32_t v = 0;
    bool found = RegReadDword("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
                              "DefaultSecureProtocols", v, 64) ||
                 RegReadDword("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
                              "DefaultSecureProtocols", v);
    char buf[64];
    std::snprintf(buf, sizeof buf, "0x%X", v);
    if (!found) {
        detail = "WinHttp DefaultSecureProtocols not set (system default protocols for WinHTTP exclude TLS 1.2 on Windows 7)";
        return false;
    }
    detail = std::string("WinHttp DefaultSecureProtocols = ") + buf + ((v & 0x800) ? " (includes TLS 1.2)" : " (TLS 1.2 NOT included)");
    return (v & 0x800) != 0;
}

}  // namespace

int CmdDoctor(CommandContext& c) {
    std::vector<Check> checks;
    auto add = [&](const std::string& n, const std::string& s, const std::string& d) { checks.push_back({n, s, d}); };
    const OsInfo& os = GetOsInfo();

    std::string osText = (os.productName.empty() ? "Windows" : os.productName) + " NT " + std::to_string(os.major) + "." +
                         std::to_string(os.minor) + "." + std::to_string(os.build) +
                         (os.servicePackMajor ? " SP" + std::to_string(os.servicePackMajor) : "") + " " + ArchName(os.nativeArch);
    add("Operating system", "INFO", osText);
    if (os.IsWindows7()) {
        add("Windows 7 support status", "WARN",
            "Microsoft ended Windows 7 security updates (ESU ended January 2023). SevenGet verifies packages but "
            "cannot make this system secure.");
        if (os.servicePackMajor < 1) add("Service Pack", "FAIL", "Windows 7 SP1 is required (TLS 1.2 updates need it)");
    }
    if (os.major < 6 || (os.major == 6 && os.minor < 1)) add("Supported OS", "FAIL", "Windows 7 SP1 or later is required");
    add("Process", "INFO", std::string(ArchName(os.processArch)) + (IsProcessElevated() ? ", elevated" : ", not elevated (fine for normal use)"));

    // Cryptography self-tests.
    Bytes digest;
    std::string abc = Sha256Hex("abc");
    add("CNG SHA-256", abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? "OK" : "FAIL",
        "bcrypt.dll known-answer test");
    PublicKey tk;
    Bytes sig;
    std::string err;
    bool ecdsaOk = ParsePublicKey(std::string("sevenget-pubkey-v1 ecdsa-p256 ") + kTestPub, tk, err) &&
                   HexDecode(kTestSig, sig) && VerifyEcdsaP256(tk, kTestMsg, sig, err);
    std::string tampered = kTestMsg;
    tampered[0] = 's';
    bool rejectsBad = !VerifyEcdsaP256(tk, tampered, sig, err);
    add("CNG ECDSA P-256", ecdsaOk && rejectsBad ? "OK" : "FAIL",
        ecdsaOk && rejectsBad ? "verifies an OpenSSL-made signature and rejects a modified message"
                              : "repository signatures cannot be verified on this system");

    // TLS.
    std::string tlsDetail;
    bool tls = ProbeTls12Support(tlsDetail);
    add("WinHTTP TLS 1.2", tls ? "OK" : "FAIL",
        tls ? tlsDetail : tlsDetail + " - install KB3140245 (Windows 7 SP1) and see docs/security.md");
    if (os.IsWindows7()) {
        std::string regDetail;
        bool reg = CheckWinHttpTlsRegistry(regDetail);
        add("WinHTTP default protocols", reg ? "OK" : "INFO",
            regDetail + (reg ? "" : "; SevenGet enables TLS 1.2 itself, other programs may need the Microsoft 'Easy fix'"));
        uint32_t disabled = 0;
        if (RegReadDword("HKLM", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client",
                         "Enabled", disabled) && disabled == 0)
            add("Schannel TLS 1.2 client", "FAIL", "TLS 1.2 is explicitly disabled in the SCHANNEL registry settings");
    }

    // Paths and database.
    const AppPaths& p = GetAppPaths();
    add("Data directory", CreateDirectories(p.dataDir) ? "OK" : "FAIL", p.dataDir);
    add("Config file", "INFO", JoinPath(p.configDir, "config.json"));
    std::string snapshot = JoinPath(p.dataDir, "installed-snapshot.json");
    bool dbOk = false;
    try {
        if (c.args.repair) c.AcquireLock();
        else c.OpenDatabase();
        std::vector<std::string> problems;
        dbOk = c.db.IntegrityCheck(problems);
        add("Database integrity", dbOk ? "OK" : "FAIL", dbOk ? DatabasePath() : Join(problems, "; "));
    } catch (const Error& e) {
        add("Database", "FAIL", e.what());
    }
    if (!dbOk && c.args.repair) {
        c.db.Close();
        c.repos.reset();
        std::string db = DatabasePath();
        std::string moved = db + ".corrupt-" + std::to_string(NowUnix());
        MoveFileReplace(db, moved);
        DeleteFileUtf8(db + "-wal");
        DeleteFileUtf8(db + "-shm");
        try {
            c.OpenDatabase();
            std::string text;
            if (ReadFileBytes(snapshot, text, 64 << 20)) {
                auto pr = ParseJson(text);
                if (!pr.ok) throw Error(kExitDatabase, "snapshot is unreadable: " + pr.error);
                c.db.ImportSnapshot(pr.value);
                add("Repair", "OK", "database rebuilt from snapshot; corrupt file kept as " + moved);
            } else {
                add("Repair", "WARN", "no snapshot found; created an empty database (corrupt file kept as " + moved + ")");
            }
            dbOk = true;
        } catch (const Error& e) {
            add("Repair", "FAIL", e.what());
        }
    } else if (!dbOk) {
        add("Repair", "INFO", "run 'sevenget doctor --repair' to rebuild the database from " + snapshot);
    }
    if (dbOk) {
        int64_t now = NowUnix();
        auto repos = c.db.ListRepos();
        if (repos.empty()) add("Repositories", "WARN", "none configured");
        for (const auto& r : repos) {
            std::string st = r.expires && now > r.expires ? "FAIL" : r.expires && now + 7 * 86400 > r.expires ? "WARN" : "OK";
            add("Repository " + r.name, st,
                "sequence " + std::to_string(r.sequence) + ", expires " + (r.expires ? FormatUtc(r.expires) : "-") +
                    ", key " + r.fingerprint.substr(0, 16) + "...");
        }
        int interrupted = 0;
        for (const auto& t : c.db.History(200))
            if (t.state == "interrupted" || t.state == "started") ++interrupted;
        if (interrupted) add("Interrupted operations", "WARN", std::to_string(interrupted) + " found in recent history (see 'sevenget history')");
    }

    Json arr = Json::Array();
    Table t({"CHECK", "STATUS", "DETAILS"});
    bool failed = false;
    for (const auto& ch : checks) {
        Color col = ch.status == "OK" ? Color::Green : ch.status == "FAIL" ? Color::Red : ch.status == "WARN" ? Color::Yellow : Color::Default;
        t.AddRow({ch.name, ch.status, ch.detail}, col);
        if (ch.status == "FAIL") failed = true;
        Json j = Json::Object();
        j.Set("check", ch.name);
        j.Set("status", ch.status);
        j.Set("detail", ch.detail);
        arr.Push(j);
    }
    c.out.Set("checks", arr);
    t.Print();
    return failed ? kExitError : kExitOk;
}

}  // namespace sg
