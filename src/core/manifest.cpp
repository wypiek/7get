#include "core/manifest.h"

#include <set>

#include "platform/http.h"
#include "util/strings.h"
#include "util/version.h"

namespace sg {

const char* InstallerTypeName(InstallerType t) {
    switch (t) {
        case InstallerType::Exe: return "exe";
        case InstallerType::Msi: return "msi";
        case InstallerType::Zip: return "zip";
    }
    return "?";
}

const char* ScopeName(Scope s) { return s == Scope::User ? "user" : "machine"; }

bool Installer::SupportsScope(Scope s) const {
    for (Scope x : scopes)
        if (x == s) return true;
    return false;
}

bool IsValidPackageId(const std::string& id) {
    if (id.empty() || id.size() > 100) return false;
    auto alnum = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };
    if (!alnum(id[0]) || !alnum(id.back())) return false;
    for (char c : id)
        if (!alnum(c) && c != '.' && c != '-' && c != '_') return false;
    if (id.find("..") != std::string::npos) return false;
    // Reserved DOS device names would be dangerous as directory names.
    static const char* reserved[] = {"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6",
                                     "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6",
                                     "lpt7", "lpt8", "lpt9"};
    std::string base = ToLowerAscii(id.substr(0, id.find('.')));
    for (const char* r : reserved)
        if (base == r) return false;
    return true;
}

bool IsValidRepoName(const std::string& name) { return name.size() <= 40 && IsValidPackageId(name); }

bool IsValidSha256Hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    return true;
}

bool IsValidGuid(const std::string& s) {
    if (s.size() != 38 || s[0] != '{' || s[37] != '}') return false;
    for (size_t i = 1; i < 37; ++i) {
        char c = s[i];
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool IsSafeArgument(const std::string& s) {
    if (s.empty() || s.size() > 512 || !IsValidUtf8(s)) return false;
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7F || c == '"') return false;
    return true;
}

namespace {

class Validator {
public:
    explicit Validator(std::vector<std::string>& errors) : errors_(errors) {}
    void Error(const std::string& where, const std::string& msg) { errors_.push_back(where + ": " + msg); }
    bool ok() const { return errors_.empty(); }

    void CheckKeys(const Json& obj, const std::string& where, std::initializer_list<const char*> allowed) {
        for (const auto& m : obj.Members()) {
            bool found = false;
            for (const char* a : allowed)
                if (m.first == a) found = true;
            if (!found) Error(where, "unknown field '" + m.first + "'");
        }
    }

    bool Str(const Json& obj, const char* key, const std::string& where, std::string& out, bool required,
             size_t maxLen = 1000) {
        const Json* v = obj.Find(key);
        if (!v) {
            if (required) Error(where, std::string("missing required field '") + key + "'");
            return false;
        }
        if (!v->IsString()) { Error(where, std::string("'") + key + "' must be a string"); return false; }
        const std::string& s = v->AsString();
        if (s.size() > maxLen) { Error(where, std::string("'") + key + "' is too long"); return false; }
        for (unsigned char c : s)
            if (c < 0x20 && c != '\n') { Error(where, std::string("'") + key + "' contains control characters"); return false; }
        if (required && Trim(s).empty()) { Error(where, std::string("'") + key + "' must not be empty"); return false; }
        out = s;
        return true;
    }

    bool StrArray(const Json& obj, const char* key, const std::string& where, std::vector<std::string>& out) {
        const Json* v = obj.Find(key);
        if (!v) return false;
        if (!v->IsArray() || v->Size() > 64) { Error(where, std::string("'") + key + "' must be an array (max 64)"); return false; }
        for (const auto& item : v->Items()) {
            if (!item.IsString()) { Error(where, std::string("'") + key + "' must contain only strings"); return false; }
            out.push_back(item.AsString());
        }
        return true;
    }

    bool IntArray(const Json& obj, const char* key, const std::string& where, std::vector<int64_t>& out) {
        const Json* v = obj.Find(key);
        if (!v) return false;
        if (!v->IsArray() || v->Size() > 64) { Error(where, std::string("'") + key + "' must be an array"); return false; }
        for (const auto& item : v->Items()) {
            if (!item.IsInteger() || item.AsInt() < -2147483648LL || item.AsInt() > 4294967295LL) {
                Error(where, std::string("'") + key + "' must contain 32-bit integers");
                return false;
            }
            out.push_back(item.AsInt());
        }
        return true;
    }

private:
    std::vector<std::string>& errors_;
};

bool IsMsiPropertyToken(const std::string& s) {
    size_t eq = s.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    std::string name = s.substr(0, eq);
    for (size_t i = 0; i < name.size(); ++i) {
        char c = name[i];
        bool ok = (c >= 'A' && c <= 'Z') || c == '_' || (i > 0 && ((c >= '0' && c <= '9') || c == '.'));
        if (!ok) return false;  // public properties are upper case
    }
    static const char* denied[] = {"TRANSFORMS", "PATCH", "REBOOT", "ALLUSERS", "MSIINSTALLPERUSER", "ACTION"};
    for (const char* d : denied)
        if (name == d) return false;
    return IsSafeArgument(s);
}

void ParseInstaller(Validator& v, const Json& j, const std::string& where, Installer& in) {
    if (!j.IsObject()) { v.Error(where, "installer must be an object"); return; }
    v.CheckKeys(j, where, {"arch", "type", "url", "sha256", "size", "minWindows", "maxWindows", "scope", "silentArgs",
                           "successExitCodes", "rebootExitCodes", "productCode", "upgradeBehavior", "uninstall",
                           "signature", "notes"});
    std::string s;
    if (v.Str(j, "arch", where, s, true, 16) && !ParseArch(s, in.arch)) v.Error(where, "unsupported arch '" + s + "'");
    if (in.arch == Arch::Arm64) v.Error(where, "arm64 installers are not supported by this SevenGet version");
    if (v.Str(j, "type", where, s, true, 16)) {
        if (s == "exe") in.type = InstallerType::Exe;
        else if (s == "msi") in.type = InstallerType::Msi;
        else if (s == "zip") in.type = InstallerType::Zip;
        else v.Error(where, "unsupported installer type '" + s + "'");
    }
    if (v.Str(j, "url", where, in.url, true, 2048) && !IsHttpsUrl(in.url)) v.Error(where, "url must be an https:// URL");
    if (v.Str(j, "sha256", where, in.sha256, true, 64)) {
        if (!IsValidSha256Hex(in.sha256)) v.Error(where, "sha256 must be 64 hex characters");
        in.sha256 = ToLowerAscii(in.sha256);
    }
    if (const Json* sz = j.Find("size")) {
        if (!sz->IsInteger() || sz->AsInt() <= 0 || sz->AsInt() > (int64_t(8) << 30)) v.Error(where, "size must be a positive integer (bytes)");
        else in.size = static_cast<uint64_t>(sz->AsInt());
    }
    if (v.Str(j, "minWindows", where, s, true, 8) && !ParseWindowsVersion(s, in.minWinMajor, in.minWinMinor))
        v.Error(where, "minWindows must look like \"6.1\"");
    if (v.Str(j, "maxWindows", where, s, false, 8)) {
        if (!ParseWindowsVersion(s, in.maxWinMajor, in.maxWinMinor)) v.Error(where, "maxWindows must look like \"6.3\"");
        else in.hasMaxWin = true;
    }
    std::vector<std::string> scopes;
    if (!v.StrArray(j, "scope", where, scopes) || scopes.empty()) v.Error(where, "scope must list \"user\" and/or \"machine\"");
    for (const auto& sc : scopes) {
        if (sc == "user") in.scopes.push_back(Scope::User);
        else if (sc == "machine") in.scopes.push_back(Scope::Machine);
        else v.Error(where, "invalid scope '" + sc + "'");
    }
    v.StrArray(j, "silentArgs", where, in.silentArgs);
    for (const auto& a : in.silentArgs) {
        if (!IsSafeArgument(a)) v.Error(where, "silentArgs contains an unsafe argument");
        else if (in.type == InstallerType::Msi && !IsMsiPropertyToken(a))
            v.Error(where, "msi silentArgs may only contain PUBLICPROPERTY=value tokens (got '" + a + "')");
    }
    if (in.type == InstallerType::Exe && in.silentArgs.empty())
        v.Error(where, "exe installers must declare silentArgs from the vendor's documentation");
    if (in.type == InstallerType::Zip && !in.silentArgs.empty()) v.Error(where, "zip packages take no silentArgs");

    v.IntArray(j, "successExitCodes", where, in.successExitCodes);
    v.IntArray(j, "rebootExitCodes", where, in.rebootExitCodes);
    if (in.successExitCodes.empty()) in.successExitCodes.push_back(0);
    if (in.type == InstallerType::Msi && in.rebootExitCodes.empty()) in.rebootExitCodes = {3010, 1641};

    if (v.Str(j, "productCode", where, in.productCode, false, 38)) {
        if (in.type != InstallerType::Msi) v.Error(where, "productCode only applies to msi installers");
        else if (!IsValidGuid(in.productCode)) v.Error(where, "productCode must be a {GUID}");
    }
    if (v.Str(j, "upgradeBehavior", where, in.upgradeBehavior, false, 32)) {
        if (in.upgradeBehavior != "install-over" && in.upgradeBehavior != "uninstall-first")
            v.Error(where, "upgradeBehavior must be install-over or uninstall-first");
    } else {
        in.upgradeBehavior = in.type == InstallerType::Msi ? "uninstall-first" : "install-over";
    }
    v.Str(j, "notes", where, in.notes, false, 2000);

    const Json* un = j.Find("uninstall");
    const std::string uw = where + ".uninstall";
    if (!un || !un->IsObject()) {
        v.Error(where, "missing 'uninstall' object");
    } else {
        v.CheckKeys(*un, uw, {"strategy", "registryKey", "quietArgs"});
        v.Str(*un, "strategy", uw, in.uninstall.strategy, true, 16);
        const std::string expected = in.type == InstallerType::Exe ? "registry" : in.type == InstallerType::Msi ? "msi" : "files";
        if (!in.uninstall.strategy.empty() && in.uninstall.strategy != expected)
            v.Error(uw, "strategy for " + std::string(InstallerTypeName(in.type)) + " installers must be '" + expected + "'");
        if (in.type == InstallerType::Exe) {
            if (v.Str(*un, "registryKey", uw, in.uninstall.registryKey, true, 200)) {
                const std::string& k = in.uninstall.registryKey;
                if (k.find_first_of("\\/") != std::string::npos || k.find("..") != std::string::npos || !IsSafeArgument(k))
                    v.Error(uw, "registryKey must be a single key name");
            }
            v.StrArray(*un, "quietArgs", uw, in.uninstall.quietArgs);
            for (const auto& a : in.uninstall.quietArgs)
                if (!IsSafeArgument(a)) v.Error(uw, "quietArgs contains an unsafe argument");
        } else if (un->Has("registryKey") || un->Has("quietArgs")) {
            v.Error(uw, "registryKey/quietArgs only apply to exe installers");
        }
    }

    if (const Json* sig = j.Find("signature")) {
        const std::string sw = where + ".signature";
        if (!sig->IsObject()) {
            v.Error(sw, "must be an object");
        } else {
            v.CheckKeys(*sig, sw, {"required", "subject", "files"});
            if (const Json* r = sig->Find("required")) {
                if (!r->IsBool()) v.Error(sw, "'required' must be boolean");
                else in.signature.required = r->AsBool();
            }
            v.Str(*sig, "subject", sw, in.signature.subject, false, 256);
            v.StrArray(*sig, "files", sw, in.signature.files);
            if (!in.signature.files.empty() && in.type != InstallerType::Zip)
                v.Error(sw, "'files' only applies to zip packages");
            if (in.type == InstallerType::Zip && in.signature.required && in.signature.files.empty())
                v.Error(sw, "zip packages requiring signatures must list the signed 'files'");
            for (const auto& f : in.signature.files)
                if (!IsSafeArgument(f) || f.find("..") != std::string::npos) v.Error(sw, "invalid file entry '" + f + "'");
        }
    }
}

}  // namespace

bool ParsePackage(const Json& j, Package& p, std::vector<std::string>& errors) {
    Validator v(errors);
    if (!j.IsObject()) {
        v.Error("package", "manifest must be a JSON object");
        return false;
    }
    std::string where = "package";
    if (const Json* idv = j.Find("id"); idv && idv->IsString()) where = "package '" + idv->AsString() + "'";
    v.CheckKeys(j, where, {"id", "name", "publisher", "description", "license", "homepage", "tags", "releases"});
    if (v.Str(j, "id", where, p.id, true, 100) && !IsValidPackageId(p.id))
        v.Error(where, "invalid package id (allowed: letters, digits, '.', '-', '_')");
    v.Str(j, "name", where, p.name, true, 200);
    v.Str(j, "publisher", where, p.publisher, true, 200);
    v.Str(j, "description", where, p.description, true, 2000);
    v.Str(j, "license", where, p.license, false, 200);
    if (v.Str(j, "homepage", where, p.homepage, false, 2048) && !IsHttpsUrl(p.homepage))
        v.Error(where, "homepage must be an https:// URL");
    v.StrArray(j, "tags", where, p.tags);
    const Json* rels = j.Find("releases");
    if (!rels || !rels->IsArray() || rels->Size() == 0) {
        v.Error(where, "'releases' must be a non-empty array");
        return false;
    }
    std::set<std::string> seen;
    for (size_t ri = 0; ri < rels->Items().size(); ++ri) {
        const Json& rj = rels->Items()[ri];
        std::string rw = where + ".releases[" + std::to_string(ri) + "]";
        if (!rj.IsObject()) { v.Error(rw, "must be an object"); continue; }
        v.CheckKeys(rj, rw, {"version", "releaseDate", "dependencies", "installers"});
        Release r;
        if (v.Str(rj, "version", rw, r.version, true, 64)) {
            if (!IsValidVersionString(r.version)) v.Error(rw, "invalid version string '" + r.version + "'");
            if (!seen.insert(ToLowerAscii(r.version)).second) v.Error(rw, "duplicate version " + r.version);
        }
        v.Str(rj, "releaseDate", rw, r.releaseDate, false, 10);
        if (const Json* deps = rj.Find("dependencies")) {
            if (!deps->IsArray()) v.Error(rw, "'dependencies' must be an array");
            else
                for (const auto& dj : deps->Items()) {
                    Dependency d;
                    if (!dj.IsObject()) { v.Error(rw, "dependency must be an object"); continue; }
                    v.CheckKeys(dj, rw + ".dependencies", {"id", "minVersion"});
                    if (v.Str(dj, "id", rw, d.id, true, 100) && !IsValidPackageId(d.id)) v.Error(rw, "invalid dependency id");
                    if (v.Str(dj, "minVersion", rw, d.minVersion, false, 64) && !IsValidVersionString(d.minVersion))
                        v.Error(rw, "invalid dependency minVersion");
                    if (d.id == p.id) v.Error(rw, "package cannot depend on itself");
                    r.dependencies.push_back(d);
                }
        }
        const Json* ins = rj.Find("installers");
        if (!ins || !ins->IsArray() || ins->Size() == 0) {
            v.Error(rw, "'installers' must be a non-empty array");
        } else {
            for (size_t ii = 0; ii < ins->Items().size(); ++ii) {
                Installer in;
                ParseInstaller(v, ins->Items()[ii], rw + ".installers[" + std::to_string(ii) + "]", in);
                r.installers.push_back(in);
            }
        }
        p.releases.push_back(r);
    }
    return v.ok();
}

Json InstallerToJson(const Installer& i) {
    Json j = Json::Object();
    j.Set("arch", ArchName(i.arch));
    j.Set("type", InstallerTypeName(i.type));
    j.Set("url", i.url);
    j.Set("sha256", i.sha256);
    if (i.size) j.Set("size", static_cast<int64_t>(i.size));
    j.Set("minWindows", std::to_string(i.minWinMajor) + "." + std::to_string(i.minWinMinor));
    if (i.hasMaxWin) j.Set("maxWindows", std::to_string(i.maxWinMajor) + "." + std::to_string(i.maxWinMinor));
    Json sc = Json::Array();
    for (Scope s : i.scopes) sc.Push(ScopeName(s));
    j.Set("scope", sc);
    if (!i.silentArgs.empty()) {
        Json a = Json::Array();
        for (const auto& s : i.silentArgs) a.Push(s);
        j.Set("silentArgs", a);
    }
    Json ok = Json::Array();
    for (auto c : i.successExitCodes) ok.Push(Json(c));
    j.Set("successExitCodes", ok);
    if (!i.rebootExitCodes.empty()) {
        Json rb = Json::Array();
        for (auto c : i.rebootExitCodes) rb.Push(Json(c));
        j.Set("rebootExitCodes", rb);
    }
    if (!i.productCode.empty()) j.Set("productCode", i.productCode);
    j.Set("upgradeBehavior", i.upgradeBehavior);
    Json un = Json::Object();
    un.Set("strategy", i.uninstall.strategy);
    if (!i.uninstall.registryKey.empty()) un.Set("registryKey", i.uninstall.registryKey);
    if (!i.uninstall.quietArgs.empty()) {
        Json a = Json::Array();
        for (const auto& s : i.uninstall.quietArgs) a.Push(s);
        un.Set("quietArgs", a);
    }
    j.Set("uninstall", un);
    Json sig = Json::Object();
    sig.Set("required", i.signature.required);
    if (!i.signature.subject.empty()) sig.Set("subject", i.signature.subject);
    if (!i.signature.files.empty()) {
        Json f = Json::Array();
        for (const auto& s : i.signature.files) f.Push(s);
        sig.Set("files", f);
    }
    j.Set("signature", sig);
    if (!i.notes.empty()) j.Set("notes", i.notes);
    return j;
}

Json PackageToJson(const Package& p) {
    Json j = Json::Object();
    j.Set("id", p.id);
    j.Set("name", p.name);
    j.Set("publisher", p.publisher);
    j.Set("description", p.description);
    if (!p.license.empty()) j.Set("license", p.license);
    if (!p.homepage.empty()) j.Set("homepage", p.homepage);
    if (!p.tags.empty()) {
        Json t = Json::Array();
        for (const auto& s : p.tags) t.Push(s);
        j.Set("tags", t);
    }
    Json rels = Json::Array();
    for (const auto& r : p.releases) {
        Json rj = Json::Object();
        rj.Set("version", r.version);
        if (!r.releaseDate.empty()) rj.Set("releaseDate", r.releaseDate);
        if (!r.dependencies.empty()) {
            Json d = Json::Array();
            for (const auto& dep : r.dependencies) {
                Json dj = Json::Object();
                dj.Set("id", dep.id);
                if (!dep.minVersion.empty()) dj.Set("minVersion", dep.minVersion);
                d.Push(dj);
            }
            rj.Set("dependencies", d);
        }
        Json ins = Json::Array();
        for (const auto& i : r.installers) ins.Push(InstallerToJson(i));
        rj.Set("installers", ins);
        rels.Push(rj);
    }
    j.Set("releases", rels);
    if (!p.repository.empty()) j.Set("repository", p.repository);
    return j;
}

}  // namespace sg
