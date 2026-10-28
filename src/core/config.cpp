#include "core/config.h"

#include "platform/winutil.h"
#include "util/json.h"
#include "util/strings.h"

namespace sg {

const std::vector<ConfigKeyInfo>& ConfigKeys() {
    static const std::vector<ConfigKeyInfo> keys = {
        {"arch", "auto", "Preferred package architecture", "auto | x86 | x64"},
        {"scope", "auto", "Default install scope (auto prefers per-user when a package supports it)",
         "auto | user | machine"},
        {"color", "auto", "Console colors", "auto | always | never"},
        {"installerPreference", "msi,exe,zip", "Installer type preference order", "comma list of msi, exe, zip"},
        {"network.proxy", "", "HTTPS proxy (empty = Internet Options / WinHTTP settings)", "host:port or empty"},
        {"network.timeoutSeconds", "60", "Network timeout in seconds", "5..3600"},
        {"network.checkRevocation", "false", "Check TLS server certificate revocation", "true | false"},
        {"cache.keepDownloads", "false", "Keep verified installers in the cache after installation", "true | false"},
        {"security.requireAuthenticode", "false",
         "Refuse installers without a valid Authenticode signature even when the manifest does not require one",
         "true | false"},
        {"security.revocation", "soft",
         "Authenticode revocation policy: soft tolerates an unreachable revocation server, hard fails",
         "soft | hard"},
        {"warnings.windows7", "true", "Show the Windows 7 end-of-support notice", "true | false"},
    };
    return keys;
}

namespace {
const ConfigKeyInfo* FindKey(const std::string& key) {
    for (const auto& k : ConfigKeys())
        if (key == k.key) return &k;
    return nullptr;
}
}  // namespace

bool Config::IsKnownKey(const std::string& key) { return FindKey(key) != nullptr; }

bool Config::Validate(const std::string& key, std::string& value, std::string& err) {
    const ConfigKeyInfo* info = FindKey(key);
    if (!info) {
        err = "unknown configuration key '" + key + "' (see 'sevenget config list')";
        return false;
    }
    std::string v = Trim(value);
    auto oneOf = [&](std::initializer_list<const char*> opts) {
        std::string l = ToLowerAscii(v);
        for (const char* o : opts)
            if (l == o) { v = o; return true; }
        return false;
    };
    bool ok = true;
    if (key == "arch") ok = oneOf({"auto", "x86", "x64"});
    else if (key == "scope") ok = oneOf({"auto", "user", "machine"});
    else if (key == "color") ok = oneOf({"auto", "always", "never"});
    else if (key == "security.revocation") ok = oneOf({"soft", "hard"});
    else if (key == "installerPreference") {
        auto parts = Split(ToLowerAscii(v), ',');
        std::vector<std::string> clean;
        for (auto& p : parts) {
            p = Trim(p);
            if (p != "msi" && p != "exe" && p != "zip") { ok = false; break; }
            for (const auto& c : clean)
                if (c == p) ok = false;
            clean.push_back(p);
        }
        if (ok) v = Join(clean, ",");
    } else if (key == "network.proxy") {
        if (!v.empty()) {
            size_t colon = v.rfind(':');
            int64_t port = 0;
            ok = colon != std::string::npos && colon > 0 && ParseInt64(v.substr(colon + 1), port) && port > 0 &&
                 port < 65536 && v.find_first_of(" \t\"/\\") == std::string::npos;
        }
    } else if (key == "network.timeoutSeconds") {
        int64_t n;
        ok = ParseInt64(v, n) && n >= 5 && n <= 3600;
    } else {
        ok = oneOf({"true", "false"});  // remaining keys are booleans
    }
    if (!ok) {
        err = "invalid value '" + value + "' for " + key + " (allowed: " + info->allowed + ")";
        return false;
    }
    value = v;
    return true;
}

void Config::Load(const std::string& path, std::vector<std::string>& warnings) {
    path_ = path;
    values_.clear();
    std::string text;
    if (!ReadFileBytes(path, text, 1 << 20)) return;  // missing file = defaults
    auto pr = ParseJson(text);
    if (!pr.ok || !pr.value.IsObject()) {
        warnings.push_back("ignoring malformed configuration file " + path + (pr.ok ? "" : ": " + pr.error));
        return;
    }
    for (const auto& m : pr.value.Members()) {
        if (!m.second.IsString()) {
            warnings.push_back("config: value of '" + m.first + "' must be a string; ignored");
            continue;
        }
        std::string v = m.second.AsString(), err;
        if (!Validate(m.first, v, err)) {
            warnings.push_back("config: " + err + "; using default");
            continue;
        }
        values_[m.first] = v;
    }
}

bool Config::Save(std::string& err) const {
    Json j = Json::Object();
    for (const auto& kv : values_) j.Set(kv.first, kv.second);
    if (!CreateDirectories(ParentPath(path_)) || !WriteFileAtomic(path_, j.Dump(true) + "\n")) {
        err = "cannot write " + path_;
        return false;
    }
    return true;
}

std::string Config::Get(const std::string& key) const {
    auto it = values_.find(key);
    if (it != values_.end()) return it->second;
    const ConfigKeyInfo* info = FindKey(key);
    return info ? info->defaultValue : "";
}

bool Config::GetBool(const std::string& key) const { return Get(key) == "true"; }

int Config::GetInt(const std::string& key) const {
    int64_t v = 0;
    ParseInt64(Get(key), v);
    return static_cast<int>(v);
}

bool Config::Set(const std::string& key, const std::string& value, std::string& err) {
    std::string v = value;
    if (!Validate(key, v, err)) return false;
    const ConfigKeyInfo* info = FindKey(key);
    if (v == info->defaultValue) values_.erase(key);
    else values_[key] = v;
    return true;
}

bool Config::IsDefault(const std::string& key) const { return values_.find(key) == values_.end(); }

}  // namespace sg
