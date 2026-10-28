// SevenGet - user configuration (%APPDATA%\SevenGet\config.json).
//
// Only the user can change these settings (`sevenget config set`). Repository
// metadata has no way to read or override them, so security-relevant settings
// such as security.requireAuthenticode can only ever be tightened by
// manifests (signature.required), never relaxed.
#pragma once

#include <map>
#include <string>
#include <vector>

namespace sg {

struct ConfigKeyInfo {
    const char* key;
    const char* defaultValue;
    const char* description;
    const char* allowed;  // human-readable allowed values
};

const std::vector<ConfigKeyInfo>& ConfigKeys();

class Config {
public:
    // Loads from path; unknown keys are ignored with a warning list, invalid
    // values fall back to defaults.
    void Load(const std::string& path, std::vector<std::string>& warnings);
    bool Save(std::string& err) const;

    // Validates and normalises a value. Returns false with err on failure.
    static bool Validate(const std::string& key, std::string& value, std::string& err);
    static bool IsKnownKey(const std::string& key);

    std::string Get(const std::string& key) const;
    bool GetBool(const std::string& key) const;
    int GetInt(const std::string& key) const;
    bool Set(const std::string& key, const std::string& value, std::string& err);
    bool IsDefault(const std::string& key) const;

private:
    std::string path_;
    std::map<std::string, std::string> values_;  // only explicitly set keys
};

}  // namespace sg
