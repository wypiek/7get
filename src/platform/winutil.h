// SevenGet - Win32 platform utilities: OS information, directories, files,
// registry reads. All functions use the wide (UTF-16) Win32 APIs internally
// and UTF-8 std::string at the interface.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sg {

enum class Arch { Unknown, X86, X64, Arm64 };
const char* ArchName(Arch a);              // "x86", "x64", "arm64"
bool ParseArch(const std::string& s, Arch& out);

struct OsInfo {
    int major = 0, minor = 0, build = 0;
    int servicePackMajor = 0;
    std::string productName;     // e.g. "Windows 7 Professional"
    Arch nativeArch = Arch::Unknown;
    Arch processArch = Arch::Unknown;
    bool isServer = false;
    bool IsWindows7() const { return major == 6 && minor == 1; }
};

// Uses RtlGetVersion (not subject to GetVersionEx compatibility shims).
const OsInfo& GetOsInfo();

bool IsProcessElevated();

// Directory conventions. Root can be overridden with %SEVENGET_HOME% for
// portable/test use; otherwise %LOCALAPPDATA%\SevenGet and %APPDATA%\SevenGet.
struct AppPaths {
    std::string dataDir;     // database, logs, user apps (local, non-roaming)
    std::string configDir;   // config.json (roaming)
    std::string cacheDir;    // downloads, repository metadata
    std::string logDir;
    std::string tempDir;     // per-transaction staging
    std::string userAppsDir; // portable packages installed with --user
    std::string machineAppsDir;  // portable packages installed machine-wide
};
const AppPaths& GetAppPaths();

std::string GetKnownFolder(int csidl);  // SHGetFolderPathW wrapper (Win7-safe)
std::string GetEnv(const std::string& name);
std::string GetExecutablePath();

// Paths
std::string JoinPath(const std::string& a, const std::string& b);
std::string ParentPath(const std::string& p);
std::string FileName(const std::string& p);
std::string GetFullPath(const std::string& p);
// True if child (after full-path normalization) is equal to or inside root.
bool IsPathInside(const std::string& root, const std::string& child);

// Files
bool FileExists(const std::string& p);
bool DirExists(const std::string& p);
bool CreateDirectories(const std::string& p);  // like mkdir -p
bool ReadFileBytes(const std::string& p, std::string& out, uint64_t maxBytes = 64ull << 20);
// Writes to "<p>.tmp-<pid>", flushes, then atomically replaces p (MoveFileEx
// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH). Never leaves a
// half-written p behind.
bool WriteFileAtomic(const std::string& p, const std::string& data);
bool DeleteFileUtf8(const std::string& p);
bool MoveFileReplace(const std::string& from, const std::string& to);
uint64_t FileSize(const std::string& p);
// Recursively deletes a directory tree without following reparse points.
bool RemoveTree(const std::string& p);
// Total bytes of files under a directory.
uint64_t DirectorySize(const std::string& p);
std::vector<std::string> ListDirectory(const std::string& p);  // names only

std::string LastErrorMessage(uint32_t code);

// Registry (read-only helpers). hive: "HKLM" or "HKCU". view: 32 or 64 (0 = default).
bool RegReadString(const std::string& hive, const std::string& subkey, const std::string& value, std::string& out,
                   int view = 0);
bool RegReadDword(const std::string& hive, const std::string& subkey, const std::string& value, uint32_t& out,
                  int view = 0);
bool RegKeyExists(const std::string& hive, const std::string& subkey, int view = 0);

// Named, per-user lock preventing concurrent mutating SevenGet operations.
class InstanceLock {
public:
    InstanceLock() = default;
    ~InstanceLock();
    InstanceLock(const InstanceLock&) = delete;
    InstanceLock& operator=(const InstanceLock&) = delete;
    bool Acquire(const std::string& lockFile);
private:
    void* handle_ = nullptr;
};

// Ctrl+C / Ctrl+Break handling: sets a flag that long operations poll.
void InstallCtrlHandler();
bool CancelRequested();
void ResetCancel();
void RequestCancel();  // for tests

}  // namespace sg
