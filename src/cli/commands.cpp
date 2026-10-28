#include "cli/commands.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>

#include "cli/context.h"
#include "core/manifest.h"
#include "install/backend.h"
#include "install/engine.h"
#include "platform/console.h"
#include "platform/http.h"
#include "util/error.h"
#include "util/log.h"
#include "util/strings.h"
#include "util/version.h"

namespace sg {

const char kSevenGetVersion[] = "1.0.0";

const char* ExitCodeName(int code) {
    switch (code) {
        case kExitOk: return "ok";
        case kExitError: return "error";
        case kExitUsage: return "usage";
        case kExitNotFound: return "not-found";
        case kExitNetwork: return "network";
        case kExitIntegrity: return "integrity";
        case kExitTrust: return "trust";
        case kExitInstallerFailed: return "installer-failed";
        case kExitCancelled: return "cancelled";
        case kExitPermission: return "permission";
        case kExitDatabase: return "database";
        case kExitIncompatible: return "incompatible";
        case kExitRebootRequired: return "reboot-required";
        case kExitBusy: return "busy";
        default: return "unknown";
    }
}

std::string DatabasePath() { return JoinPath(GetAppPaths().dataDir, "sevenget.db"); }

void CommandContext::OpenDatabase() {
    if (!db.IsOpen()) db.Open(DatabasePath());
    if (!repos) repos.reset(new RepositoryManager(db));
}

void CommandContext::AcquireLock() {
    if (lock) return;
    CreateDirectories(GetAppPaths().dataDir);
    lock.reset(new InstanceLock());
    if (!lock->Acquire(JoinPath(GetAppPaths().dataDir, "sevenget.lock"))) {
        lock.reset();
        throw Error(kExitBusy, "another SevenGet operation is in progress", "wait for it to finish and try again");
    }
    OpenDatabase();
    for (const auto& t : db.RecoverInterrupted())
        Warn("a previous " + t.action + " of " + t.packageId + " (" + FormatUtc(t.startedAt) +
             ") was interrupted; its state was not recorded as successful. Verify the program and re-run the command "
             "if needed.");
}

void CommandContext::LoadRepositories(bool allowExpired) {
    OpenDatabase();
    std::vector<std::string> w;
    repos->LoadAll(allowExpired, w);
    for (auto& s : w) Warn(s);
    if (db.ListRepos().empty())
        Warn("no repositories are configured; add one with 'sevenget repo add <url>' (see README)");
}

ResolveOptions CommandContext::MakeResolveOptions() const {
    ResolveOptions o;
    o.version = args.version;
    std::string arch = !args.arch.empty() ? args.arch : config.Get("arch");
    if (ToLowerAscii(arch) != "auto" && !ParseArch(arch, o.arch))
        throw Error(kExitUsage, "invalid --arch value '" + arch + "' (use x86, x64 or auto)");
    if (args.user) { o.scopeSpecified = true; o.scope = Scope::User; }
    else if (args.machine) { o.scopeSpecified = true; o.scope = Scope::Machine; }
    else if (config.Get("scope") != "auto") {
        o.scopeSpecified = true;
        o.scope = config.Get("scope") == "user" ? Scope::User : Scope::Machine;
    }
    o.typePreference.clear();
    for (const auto& t : Split(config.Get("installerPreference"), ',')) {
        InstallerType it;
        if (InstallerTypeFromName(Trim(t), it)) o.typePreference.push_back(it);
    }
    for (InstallerType t : {InstallerType::Msi, InstallerType::Exe, InstallerType::Zip})
        if (std::find(o.typePreference.begin(), o.typePreference.end(), t) == o.typePreference.end())
            o.typePreference.push_back(t);
    return o;
}

void CommandContext::Warn(const std::string& w) {
    warnings.push_back(w);
    Console::Warn(w);
}

namespace {

// ---------------------------------------------------------------- help text

struct CommandHelp {
    const char* name;
    const char* usage;
    const char* summary;
    const char* details;
};

const CommandHelp kHelp[] = {
    {"help", "sevenget help [command]", "Show help for SevenGet or one command", ""},
    {"version", "sevenget version", "Show version and platform information", ""},
    {"search", "sevenget search [query]", "Search packages by id, name, tag or description",
     "Shows the newest release compatible with this Windows version and architecture."},
    {"info", "sevenget info <package>", "Show package details and every release's compatibility", ""},
    {"install", "sevenget install <package> [--version V] [--arch x86|x64] [--user|--machine] [--dry-run] [--yes]",
     "Download, verify and install a package",
     "Selects the newest release explicitly marked compatible with this system unless --version is given.\n"
     "Machine-wide exe/msi installers request administrator rights through UAC; --user installs never do."},
    {"uninstall", "sevenget uninstall <package> [--user|--machine] [--dry-run] [--yes] [--force]",
     "Remove a package that SevenGet installed",
     "Uses only the ownership information recorded at install time (uninstall registry key, MSI ProductCode or\n"
     "the list of extracted files). Software not installed by SevenGet is never touched."},
    {"update", "sevenget update", "Refresh signed metadata of all enabled repositories", ""},
    {"upgrade", "sevenget upgrade <package>|--all [--version V] [--dry-run] [--yes]",
     "Upgrade installed packages to the newest compatible release", ""},
    {"list", "sevenget list", "List packages installed by SevenGet", ""},
    {"outdated", "sevenget outdated", "List installed packages with a newer compatible release", ""},
    {"download", "sevenget download <package> [--version V] [--arch A] [--output DIR]",
     "Download and verify a package without installing it", "The file is saved to DIR (default: current directory)."},
    {"clean", "sevenget clean [--all]", "Delete cached downloads and temporary files",
     "--all also removes cached repository metadata (run 'sevenget update' afterwards)."},
    {"doctor", "sevenget doctor [--repair]", "Check TLS, cryptography, database and repository health",
     "--repair rebuilds a corrupted database from the last snapshot."},
    {"history", "sevenget history", "Show recent install/upgrade/uninstall transactions", ""},
    {"repo", "sevenget repo list | add <url> [--name N] [--key-file F] [--fingerprint FP] [--replace] | remove <name>",
     "Manage repositories and their signing keys",
     "'repo add' shows the repository key fingerprint and asks you to confirm it. For unattended use pass\n"
     "--fingerprint with the value published by the repository operator (with --yes). <url> is an https://\n"
     "URL or an absolute local/UNC directory."},
    {"config", "sevenget config list | get <key> | set <key> <value>", "Show or change settings", ""},
};

void PrintGeneralHelp() {
    Console::OutLine(std::string("SevenGet ") + kSevenGetVersion + " - native package manager for Windows 7 and later",
                     Color::White);
    Console::OutLine();
    Console::OutLine("Usage: sevenget <command> [options]");
    Console::OutLine();
    Console::OutLine("Commands:", Color::White);
    Table t({"COMMAND", "DESCRIPTION"});
    for (const auto& h : kHelp) t.AddRow({std::string("  ") + h.name, h.summary});
    t.Print();
    Console::OutLine();
    Console::OutLine("Options:", Color::White);
    Table o({"OPTION", "DESCRIPTION"});
    o.AddRow({"  --help, -h", "Show help"});
    o.AddRow({"  --version", "Show SevenGet version (or select a package version after a command)"});
    o.AddRow({"  --yes, -y", "Do not ask for confirmation"});
    o.AddRow({"  --quiet, -q / --verbose", "Less / more output"});
    o.AddRow({"  --json", "Machine-readable output on stdout"});
    o.AddRow({"  --arch x86|x64|auto", "Select package architecture"});
    o.AddRow({"  --user / --machine", "Per-user or machine-wide installation"});
    o.AddRow({"  --dry-run", "Show what would happen without changing anything"});
    o.AddRow({"  --no-color", "Disable colors"});
    o.Print();
    Console::OutLine();
    Console::OutLine("Exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 network, 5 integrity, 6 trust,");
    Console::OutLine("            7 installer failed, 8 cancelled, 9 permission, 10 database, 11 incompatible,");
    Console::OutLine("            12 reboot required, 13 busy. See docs/commands.md.");
}

int CmdHelp(CommandContext& c) {
    std::string topic = c.args.positional.empty() ? (c.args.command == "help" ? "" : c.args.command)
                                                  : c.args.positional[0];
    if (topic.empty()) {
        PrintGeneralHelp();
        return kExitOk;
    }
    for (const auto& h : kHelp) {
        if (topic == h.name) {
            Console::OutLine(h.summary, Color::White);
            Console::OutLine();
            Console::OutLine("Usage: " + std::string(h.usage));
            if (*h.details) {
                Console::OutLine();
                Console::OutLine(h.details);
            }
            return kExitOk;
        }
    }
    throw Error(kExitUsage, "unknown command '" + topic + "'");
}

int CmdVersion(CommandContext& c) {
    const OsInfo& os = GetOsInfo();
    std::string build =
#if defined(_MSC_VER)
        "MSVC " + std::to_string(_MSC_VER);
#elif defined(__GNUC__)
        "GCC " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + " (mingw-w64)";
#else
        "unknown compiler";
#endif
    c.out.Set("version", kSevenGetVersion);
    c.out.Set("buildArch", ArchName(os.processArch));
    c.out.Set("compiler", build);
    c.out.Set("targetWindows", "6.1");
    Json osj = Json::Object();
    osj.Set("name", os.productName);
    osj.Set("version", std::to_string(os.major) + "." + std::to_string(os.minor) + "." + std::to_string(os.build));
    osj.Set("servicePack", os.servicePackMajor);
    osj.Set("arch", ArchName(os.nativeArch));
    c.out.Set("os", osj);
    Console::OutLine(std::string("SevenGet ") + kSevenGetVersion, Color::White);
    Console::OutLine("Native package manager for Windows");
    Console::OutLine("Build:   " + std::string(ArchName(os.processArch)) + ", " + build + ", targets Windows NT 6.1+");
    Console::OutLine("System:  " + (os.productName.empty() ? "Windows" : os.productName) + " (NT " +
                     std::to_string(os.major) + "." + std::to_string(os.minor) + "." + std::to_string(os.build) +
                     (os.servicePackMajor ? ", SP" + std::to_string(os.servicePackMajor) : "") + ", " +
                     ArchName(os.nativeArch) + ")");
    return kExitOk;
}

std::string RequireOne(CommandContext& c, const char* what) {
    if (c.args.positional.size() != 1)
        throw Error(kExitUsage, std::string("expected exactly one ") + what + " (see 'sevenget help " + c.args.command + "')");
    return c.args.positional[0];
}

std::string InstalledStatus(CommandContext& c, const Package& p, const Release* best) {
    auto recs = c.db.FindInstalled(p.id);
    if (recs.empty()) return best ? "Available" : "Incompatible";
    if (best && CompareVersions(best->version, recs.front().version) > 0) return "Upgradable (" + recs.front().version + ")";
    return "Installed";
}

int CmdSearch(CommandContext& c) {
    if (c.args.positional.size() > 1) throw Error(kExitUsage, "search takes at most one query (quote multi-word queries)");
    std::string q = c.args.positional.empty() ? "" : c.args.positional[0];
    c.LoadRepositories(true);
    PlatformInfo plat = PlatformInfo::Current();
    ResolveOptions ro = c.MakeResolveOptions();
    ro.version.clear();
    Table t({"ID", "NAME", "VERSION", "ARCH", "TYPE", "STATUS"});
    Json arr = Json::Array();
    for (const Package* p : c.repos->Search(q)) {
        ResolveResult rr = ResolvePackage(*p, plat, ro);
        const Release* best = rr.ok ? rr.candidate.release : nullptr;
        std::string status = InstalledStatus(c, *p, best);
        t.AddRow({p->id, p->name, best ? best->version : "-", rr.ok ? ArchName(rr.candidate.installer->arch) : "-",
                  rr.ok ? InstallerTypeName(rr.candidate.installer->type) : "-", status},
                 status == "Incompatible" ? Color::Gray : Color::Default);
        Json j = Json::Object();
        j.Set("id", p->id);
        j.Set("name", p->name);
        j.Set("publisher", p->publisher);
        j.Set("repository", p->repository);
        j.Set("compatibleVersion", best ? Json(best->version) : Json());
        j.Set("arch", rr.ok ? Json(ArchName(rr.candidate.installer->arch)) : Json());
        j.Set("status", status);
        arr.Push(j);
    }
    c.out.Set("results", arr);
    if (t.Empty()) {
        Console::OutLine("No packages found" + (q.empty() ? std::string() : " matching '" + q + "'") + ".");
        return kExitNotFound;
    }
    t.Print();
    return kExitOk;
}

int CmdInfo(CommandContext& c) {
    std::string id = RequireOne(c, "package id");
    c.LoadRepositories(true);
    const Package* p = c.repos->Find(id);
    if (!p) throw Error(kExitNotFound, "package '" + id + "' was not found", "try 'sevenget search " + id + "'");
    PlatformInfo plat = PlatformInfo::Current();
    ResolveOptions ro = c.MakeResolveOptions();
    ResolveResult rr = ResolvePackage(*p, plat, ro);
    Json j = PackageToJson(*p);
    if (rr.ok) j.Set("selected", CandidateToJson(rr.candidate));
    else j.Set("selectionError", rr.error);
    Json inst = Json::Array();
    for (const auto& r : c.db.FindInstalled(p->id)) {
        Json ij = Json::Object();
        ij.Set("version", r.version);
        ij.Set("scope", r.scope);
        ij.Set("arch", r.arch);
        inst.Push(ij);
    }
    j.Set("installed", inst);
    c.out.Set("package", j);

    auto line = [](const std::string& k, const std::string& v) {
        if (v.empty()) return;
        Console::Out(k, Color::Cyan);
        Console::OutLine(std::string(k.size() < 14 ? 14 - k.size() : 1, ' ') + v);
    };
    Console::OutLine(p->name, Color::White);
    line("Id:", p->id);
    line("Publisher:", p->publisher);
    line("Description:", p->description);
    line("License:", p->license);
    line("Homepage:", p->homepage);
    line("Tags:", Join(p->tags, ", "));
    line("Repository:", p->repository);
    for (const auto& r : c.db.FindInstalled(p->id)) line("Installed:", r.version + " (" + r.scope + ", " + r.arch + ")");
    if (rr.ok)
        line("Selected:", rr.candidate.release->version + " " + ArchName(rr.candidate.installer->arch) + " " +
                              InstallerTypeName(rr.candidate.installer->type) + " (" + ScopeName(rr.candidate.scope) + ")");
    else
        line("Selected:", "none - " + rr.error);
    Console::OutLine();
    Table t({"VERSION", "ARCH", "TYPE", "WINDOWS", "SCOPE", "SIGNED", "COMPATIBLE"});
    std::vector<const Release*> rels;
    for (const auto& r : p->releases) rels.push_back(&r);
    std::sort(rels.begin(), rels.end(), [](const Release* a, const Release* b) { return CompareVersions(a->version, b->version) > 0; });
    for (const Release* r : rels) {
        for (const auto& in : r->installers) {
            std::string why;
            bool compat = IsInstallerCompatible(in, plat, why) && !AcceptableArchs(plat, in.arch).empty() &&
                          [&] {
                              for (Arch a : AcceptableArchs(plat, Arch::Unknown))
                                  if (a == in.arch) return true;
                              return false;
                          }();
            std::string win = std::to_string(in.minWinMajor) + "." + std::to_string(in.minWinMinor) + "+";
            if (in.hasMaxWin) win = std::to_string(in.minWinMajor) + "." + std::to_string(in.minWinMinor) + "-" +
                                    std::to_string(in.maxWinMajor) + "." + std::to_string(in.maxWinMinor);
            std::vector<std::string> scopes;
            for (Scope s : in.scopes) scopes.push_back(ScopeName(s));
            bool selected = rr.ok && rr.candidate.installer == &in;
            t.AddRow({r->version + (selected ? " *" : ""), ArchName(in.arch), InstallerTypeName(in.type), win,
                      Join(scopes, "/"), in.signature.required ? "required" : "no",
                      compat ? "yes" : (why.empty() ? "no (arch)" : "no")},
                     selected ? Color::Green : compat ? Color::Default : Color::Gray);
        }
    }
    t.Print();
    for (const Release* r : rels)
        for (const auto& in : r->installers)
            if (!in.notes.empty()) {
                Console::OutLine();
                Console::OutLine("Note (" + r->version + " " + ArchName(in.arch) + "): " + in.notes, Color::Gray);
                break;
            }
    return kExitOk;
}

int CmdList(CommandContext& c) {
    if (!c.args.positional.empty()) throw Error(kExitUsage, "list takes no arguments");
    c.OpenDatabase();
    Table t({"ID", "NAME", "VERSION", "ARCH", "TYPE", "SCOPE", "STATUS"});
    Json arr = Json::Array();
    for (const auto& r : c.db.ListInstalled()) {
        InstallerType it;
        bool present = InstallerTypeFromName(r.installerType, it) && CreateBackend(it)->IsPresent(r);
        std::string status = present ? "Installed" : "Missing (removed outside SevenGet?)";
        t.AddRow({r.packageId, r.name, r.version, r.arch, r.installerType, r.scope, status},
                 present ? Color::Default : Color::Yellow);
        Json j = Json::Object();
        j.Set("id", r.packageId);
        j.Set("name", r.name);
        j.Set("version", r.version);
        j.Set("arch", r.arch);
        j.Set("installerType", r.installerType);
        j.Set("scope", r.scope);
        j.Set("repository", r.repository);
        j.Set("installLocation", r.installLocation);
        j.Set("installedAt", FormatUtc(r.installedAt));
        j.Set("updatedAt", FormatUtc(r.updatedAt));
        j.Set("dependency", r.dependency);
        j.Set("present", present);
        arr.Push(j);
        if (Console::Options().verbose && !r.installLocation.empty())
            Console::Debug(r.packageId + " -> " + r.installLocation);
    }
    c.out.Set("installed", arr);
    if (t.Empty()) {
        Console::OutLine("No packages installed by SevenGet.");
        return kExitOk;
    }
    t.Print();
    return kExitOk;
}

int CmdOutdated(CommandContext& c) {
    if (!c.args.positional.empty()) throw Error(kExitUsage, "outdated takes no arguments");
    c.LoadRepositories(true);
    PlatformInfo plat = PlatformInfo::Current();
    Table t({"ID", "INSTALLED", "AVAILABLE", "ARCH", "SCOPE", "REPOSITORY"});
    Json arr = Json::Array();
    for (const auto& r : c.db.ListInstalled()) {
        const Package* p = c.repos->Find(r.packageId);
        if (!p) continue;
        ResolveOptions ro = c.MakeResolveOptions();
        ro.version.clear();
        ro.scopeSpecified = true;
        ro.scope = r.scope == "machine" ? Scope::Machine : Scope::User;
        ParseArch(r.arch, ro.arch);
        ResolveResult rr = ResolvePackage(*p, plat, ro);
        if (!rr.ok || CompareVersions(rr.candidate.release->version, r.version) <= 0) continue;
        t.AddRow({r.packageId, r.version, rr.candidate.release->version, r.arch, r.scope, p->repository});
        Json j = Json::Object();
        j.Set("id", r.packageId);
        j.Set("installed", r.version);
        j.Set("available", rr.candidate.release->version);
        j.Set("scope", r.scope);
        arr.Push(j);
    }
    c.out.Set("outdated", arr);
    if (t.Empty()) {
        Console::OutLine("All installed packages are up to date.");
        return kExitOk;
    }
    t.Print();
    return kExitOk;
}

int CmdHistory(CommandContext& c) {
    c.OpenDatabase();
    Table t({"ID", "DATE (UTC)", "ACTION", "PACKAGE", "FROM", "TO", "STATE"});
    Json arr = Json::Array();
    for (const auto& h : c.db.History(50)) {
        t.AddRow({std::to_string(h.id), FormatUtc(h.startedAt), h.action, h.packageId, h.fromVersion, h.toVersion, h.state},
                 h.state == "succeeded" ? Color::Default : Color::Yellow);
        Json j = Json::Object();
        j.Set("id", h.id);
        j.Set("started", FormatUtc(h.startedAt));
        j.Set("action", h.action);
        j.Set("package", h.packageId);
        j.Set("fromVersion", h.fromVersion);
        j.Set("toVersion", h.toVersion);
        j.Set("scope", h.scope);
        j.Set("state", h.state);
        j.Set("message", h.message);
        arr.Push(j);
    }
    c.out.Set("history", arr);
    if (t.Empty()) Console::OutLine("No transactions recorded.");
    else t.Print();
    return kExitOk;
}

EngineOptions MakeEngineOptions(CommandContext& c) {
    EngineOptions o;
    o.yes = c.args.yes;
    o.dryRun = c.args.dryRun;
    o.force = c.args.force;
    o.resolve = c.MakeResolveOptions();
    return o;
}

int CmdInstall(CommandContext& c) {
    std::string id = RequireOne(c, "package id");
    if (!c.args.dryRun) c.AcquireLock();
    c.LoadRepositories(false);
    Engine e(c.db, *c.repos, c.config);
    return e.Install(id, MakeEngineOptions(c), c.out);
}

int CmdUninstall(CommandContext& c) {
    std::string id = RequireOne(c, "package id");
    if (!c.args.version.empty()) throw Error(kExitUsage, "uninstall does not take --version");
    if (!c.args.dryRun) c.AcquireLock();
    c.LoadRepositories(true);
    Engine e(c.db, *c.repos, c.config);
    return e.Uninstall(id, MakeEngineOptions(c), c.out);
}

int CmdUpgrade(CommandContext& c) {
    if (c.args.all == !c.args.positional.empty() || c.args.positional.size() > 1)
        throw Error(kExitUsage, "use 'sevenget upgrade <package>' or 'sevenget upgrade --all'");
    if (c.args.all && !c.args.version.empty()) throw Error(kExitUsage, "--version cannot be combined with --all");
    if (!c.args.dryRun) c.AcquireLock();
    c.LoadRepositories(false);
    Engine e(c.db, *c.repos, c.config);
    return e.Upgrade(c.args.positional, c.args.all, MakeEngineOptions(c), c.out);
}

int CmdDownload(CommandContext& c) {
    std::string id = RequireOne(c, "package id");
    c.LoadRepositories(false);
    Engine e(c.db, *c.repos, c.config);
    return e.Download(id, MakeEngineOptions(c), c.args.output, c.out);
}

using Handler = int (*)(CommandContext&);

struct CommandEntry {
    const char* name;
    Handler fn;
};

const CommandEntry kCommands[] = {
    {"help", CmdHelp},         {"version", CmdVersion},   {"search", CmdSearch},     {"info", CmdInfo},
    {"install", CmdInstall},   {"uninstall", CmdUninstall}, {"update", CmdUpdate},   {"upgrade", CmdUpgrade},
    {"list", CmdList},         {"outdated", CmdOutdated}, {"download", CmdDownload}, {"clean", CmdClean},
    {"doctor", CmdDoctor},     {"repo", CmdRepo},         {"config", CmdConfig},     {"history", CmdHistory},
};

}  // namespace

int RunCli(const std::vector<std::string>& argv) {
    CommandContext c;
    ParseError perr;
    c.args = ParseArgs(argv, perr);

    std::vector<std::string> cfgWarnings;
    c.config.Load(JoinPath(GetAppPaths().configDir, "config.json"), cfgWarnings);

    ConsoleOptions co;
    std::string color = c.config.Get("color");
    co.color = !c.args.noColor && color != "never" && GetEnv("NO_COLOR").empty();
    co.quiet = c.args.quiet;
    co.verbose = c.args.verbose;
    co.json = c.args.json;
    Console::Init(co);
    for (const auto& w : cfgWarnings) c.Warn(w);

    HttpOptions ho;
    ho.proxy = c.config.Get("network.proxy");
    ho.timeoutSeconds = c.config.GetInt("network.timeoutSeconds");
    ho.checkRevocation = c.config.GetBool("network.checkRevocation");
    SetHttpOptions(ho);
    Log::Init(GetAppPaths().logDir);

    int code = kExitOk;
    try {
        if (perr.failed) throw Error(kExitUsage, perr.message);
        if (c.args.showVersion && c.args.command.empty()) c.args.command = "version";
        if (c.args.command.empty()) {
            if (c.args.json) throw Error(kExitUsage, "no command given");
            PrintGeneralHelp();
            return c.args.help ? kExitOk : kExitUsage;
        }
        c.out.Set("command", c.args.command);
        if (c.args.help && c.args.command != "help") {
            c.args.positional.insert(c.args.positional.begin(), c.args.command);
            c.args.command = "help";
        }
        Handler fn = nullptr;
        for (const auto& e : kCommands)
            if (c.args.command == e.name) fn = e.fn;
        if (!fn) throw Error(kExitUsage, "unknown command '" + c.args.command + "' (see 'sevenget help')");
        Log::Info("command: " + c.args.command + (c.args.positional.empty() ? "" : " " + Join(c.args.positional, " ")));
        code = fn(c);
    } catch (const Error& e) {
        code = e.code();
        Console::Error(e.what());
        if (!e.hint().empty()) Console::Info("  " + e.hint());
        Json err = Json::Object();
        err.Set("code", e.code());
        err.Set("kind", ExitCodeName(e.code()));
        err.Set("message", e.what());
        if (!e.hint().empty()) err.Set("hint", e.hint());
        c.out.Set("error", err);
        Log::Error(std::string(c.args.command) + ": " + e.what());
    } catch (const std::bad_alloc&) {
        code = kExitError;
        Console::Error("out of memory");
    } catch (const std::exception& e) {
        code = kExitError;
        Console::Error(std::string("internal error: ") + e.what());
        Json err = Json::Object();
        err.Set("code", kExitError);
        err.Set("kind", "error");
        err.Set("message", e.what());
        c.out.Set("error", err);
    }
    if (c.args.json) {
        c.out.Set("ok", code == kExitOk || code == kExitRebootRequired);
        c.out.Set("exitCode", code);
        if (!c.warnings.empty()) {
            Json w = Json::Array();
            for (const auto& s : c.warnings) w.Push(s);
            c.out.Set("warnings", w);
        }
        Console::WriteJson(c.out.Dump(true));
    }
    return code;
}

}  // namespace sg
