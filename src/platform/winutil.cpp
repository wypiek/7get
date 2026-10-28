#include "platform/winutil.h"

#include <windows.h>
#include <shlobj.h>

#include <atomic>
#include <cstdio>

#include "util/strings.h"

namespace sg {

const char* ArchName(Arch a) {
    switch (a) {
        case Arch::X86: return "x86";
        case Arch::X64: return "x64";
        case Arch::Arm64: return "arm64";
        default: return "unknown";
    }
}

bool ParseArch(const std::string& s, Arch& out) {
    std::string l = ToLowerAscii(s);
    if (l == "x86" || l == "i386" || l == "win32") { out = Arch::X86; return true; }
    if (l == "x64" || l == "amd64" || l == "x86_64") { out = Arch::X64; return true; }
    if (l == "arm64") { out = Arch::Arm64; return true; }
    return false;
}

namespace {

Arch FromProcessorArchitecture(WORD a) {
    switch (a) {
        case PROCESSOR_ARCHITECTURE_INTEL: return Arch::X86;
        case PROCESSOR_ARCHITECTURE_AMD64: return Arch::X64;
#ifdef PROCESSOR_ARCHITECTURE_ARM64
        case PROCESSOR_ARCHITECTURE_ARM64: return Arch::Arm64;
#endif
        default: return Arch::Unknown;
    }
}

// \\?\ prefix for long absolute paths so deep ZIP trees work on Windows 7,
// which has no longPathAware opt-in.
std::wstring LongPath(const std::string& p) {
    std::wstring w = Widen(p);
    for (auto& c : w)
        if (c == L'/') c = L'\\';
    if (w.size() >= 240 && w.size() > 2 && w[1] == L':' && w.compare(0, 4, L"\\\\?\\") != 0)
        return L"\\\\?\\" + w;
    if (w.size() >= 240 && w.compare(0, 2, L"\\\\") == 0 && w.compare(0, 4, L"\\\\?\\") != 0)
        return L"\\\\?\\UNC\\" + w.substr(2);
    return w;
}

}  // namespace

const OsInfo& GetOsInfo() {
    static OsInfo info = [] {
        OsInfo o;
        typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOEXW*);
        OSVERSIONINFOEXW v{};
        v.dwOSVersionInfoSize = sizeof v;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto fn = ntdll ? reinterpret_cast<RtlGetVersionFn>(
                              reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")))
                        : nullptr;
        if (fn && fn(&v) == 0) {
            o.major = static_cast<int>(v.dwMajorVersion);
            o.minor = static_cast<int>(v.dwMinorVersion);
            o.build = static_cast<int>(v.dwBuildNumber);
            o.servicePackMajor = v.wServicePackMajor;
            o.isServer = v.wProductType != VER_NT_WORKSTATION;
        }
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        o.nativeArch = FromProcessorArchitecture(si.wProcessorArchitecture);
#if defined(_M_X64) || defined(__x86_64__)
        o.processArch = Arch::X64;
#elif defined(_M_IX86) || defined(__i386__)
        o.processArch = Arch::X86;
#else
        o.processArch = Arch::Unknown;
#endif
        std::string name;
        if (RegReadString("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", name, 64) ||
            RegReadString("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", name))
            o.productName = name;
        // Windows 11 still reports "Windows 10" in ProductName.
        if (o.major == 10 && o.build >= 22000 && StartsWith(o.productName, "Windows 10"))
            o.productName.replace(0, 10, "Windows 11");
        return o;
    }();
    return info;
}

bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof elev, &len);
    CloseHandle(token);
    return ok && elev.TokenIsElevated;
}

std::string GetKnownFolder(int csidl) {
    wchar_t buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl | CSIDL_FLAG_CREATE, nullptr, SHGFP_TYPE_CURRENT, buf)))
        return Narrow(buf);
    if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buf))) return Narrow(buf);
    return {};
}

std::string GetEnv(const std::string& name) {
    std::wstring wn = Widen(name);
    DWORD n = GetEnvironmentVariableW(wn.c_str(), nullptr, 0);
    if (n == 0) return {};
    std::wstring buf(n, L'\0');
    n = GetEnvironmentVariableW(wn.c_str(), &buf[0], n);
    buf.resize(n);
    return Narrow(buf);
}

std::string GetExecutablePath() {
    std::wstring buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, &buf[0], static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return Narrow(buf);
}

const AppPaths& GetAppPaths() {
    static AppPaths paths = [] {
        AppPaths p;
        std::string home = GetEnv("SEVENGET_HOME");
        if (!home.empty()) {
            home = GetFullPath(home);
            p.dataDir = home;
            p.configDir = home;
        } else {
            std::string local = GetKnownFolder(CSIDL_LOCAL_APPDATA);
            std::string roaming = GetKnownFolder(CSIDL_APPDATA);
            if (local.empty()) local = GetEnv("LOCALAPPDATA");
            if (roaming.empty()) roaming = GetEnv("APPDATA");
            p.dataDir = JoinPath(local, "SevenGet");
            p.configDir = JoinPath(roaming, "SevenGet");
        }
        p.cacheDir = JoinPath(p.dataDir, "cache");
        p.logDir = JoinPath(p.dataDir, "logs");
        p.tempDir = JoinPath(p.dataDir, "tmp");
        p.userAppsDir = JoinPath(p.dataDir, "apps");
        std::string pf = GetKnownFolder(CSIDL_PROGRAM_FILES);
        if (pf.empty()) pf = GetEnv("ProgramFiles");
        p.machineAppsDir = JoinPath(pf, "SevenGet Apps");
        return p;
    }();
    return paths;
}

std::string JoinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    char last = a.back();
    if (last == '\\' || last == '/') return a + b;
    return a + "\\" + b;
}

std::string ParentPath(const std::string& p) {
    size_t pos = p.find_last_of("\\/");
    if (pos == std::string::npos) return {};
    if (pos == 2 && p.size() > 1 && p[1] == ':') return p.substr(0, 3);
    return p.substr(0, pos);
}

std::string FileName(const std::string& p) {
    size_t pos = p.find_last_of("\\/");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

std::string GetFullPath(const std::string& p) {
    std::wstring w = Widen(p);
    DWORD n = GetFullPathNameW(w.c_str(), 0, nullptr, nullptr);
    if (n == 0) return p;
    std::wstring buf(n, L'\0');
    n = GetFullPathNameW(w.c_str(), n, &buf[0], nullptr);
    buf.resize(n);
    return Narrow(buf);
}

bool IsPathInside(const std::string& root, const std::string& child) {
    std::wstring r = ToLowerAsciiW(Widen(GetFullPath(root)));
    std::wstring c = ToLowerAsciiW(Widen(GetFullPath(child)));
    // Non-ASCII case folding via CharLowerBuffW for robustness.
    if (!r.empty()) CharLowerBuffW(&r[0], static_cast<DWORD>(r.size()));
    if (!c.empty()) CharLowerBuffW(&c[0], static_cast<DWORD>(c.size()));
    while (!r.empty() && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
    if (c == r) return true;
    return c.size() > r.size() && c.compare(0, r.size(), r) == 0 && c[r.size()] == L'\\';
}

bool FileExists(const std::string& p) {
    DWORD a = GetFileAttributesW(LongPath(p).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool DirExists(const std::string& p) {
    DWORD a = GetFileAttributesW(LongPath(p).c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

bool CreateDirectories(const std::string& p) {
    if (p.empty()) return false;
    if (DirExists(p)) return true;
    std::string parent = ParentPath(p);
    if (!parent.empty() && parent != p && !DirExists(parent))
        if (!CreateDirectories(parent)) return false;
    if (CreateDirectoryW(LongPath(p).c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS && DirExists(p);
}

bool ReadFileBytes(const std::string& p, std::string& out, uint64_t maxBytes) {
    HANDLE h = CreateFileW(LongPath(p).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || static_cast<uint64_t>(size.QuadPart) > maxBytes) {
        CloseHandle(h);
        return false;
    }
    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    size_t off = 0;
    while (off < out.size()) {
        DWORD got = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - off, 1 << 20));
        if (!ReadFile(h, &out[off], want, &got, nullptr) || got == 0) {
            CloseHandle(h);
            return false;
        }
        off += got;
    }
    CloseHandle(h);
    return true;
}

bool WriteFileAtomic(const std::string& p, const std::string& data) {
    std::string tmp = p + ".tmp-" + std::to_string(GetCurrentProcessId());
    HANDLE h = CreateFileW(LongPath(tmp).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t off = 0;
    bool ok = true;
    while (off < data.size()) {
        DWORD wrote = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - off, 1 << 20));
        if (!WriteFile(h, data.data() + off, want, &wrote, nullptr)) { ok = false; break; }
        off += wrote;
    }
    if (ok) ok = FlushFileBuffers(h) != 0;
    CloseHandle(h);
    if (ok) ok = MoveFileExW(LongPath(tmp).c_str(), LongPath(p).c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(LongPath(tmp).c_str());
    return ok;
}

bool DeleteFileUtf8(const std::string& p) {
    std::wstring w = LongPath(p);
    if (DeleteFileW(w.c_str())) return true;
    if (GetLastError() == ERROR_ACCESS_DENIED) {
        DWORD a = GetFileAttributesW(w.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesW(w.c_str(), a & ~FILE_ATTRIBUTE_READONLY);
            return DeleteFileW(w.c_str()) != 0;
        }
    }
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool MoveFileReplace(const std::string& from, const std::string& to) {
    return MoveFileExW(LongPath(from).c_str(), LongPath(to).c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

uint64_t FileSize(const std::string& p) {
    WIN32_FILE_ATTRIBUTE_DATA d{};
    if (!GetFileAttributesExW(LongPath(p).c_str(), GetFileExInfoStandard, &d)) return 0;
    return (static_cast<uint64_t>(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
}

std::vector<std::string> ListDirectory(const std::string& p) {
    std::vector<std::string> out;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(LongPath(JoinPath(p, "*")).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return out;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        out.push_back(Narrow(n));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return out;
}

bool RemoveTree(const std::string& p) {
    std::wstring wp = LongPath(p);
    DWORD attr = GetFileAttributesW(wp.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return true;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) return DeleteFileUtf8(p);
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) return RemoveDirectoryW(wp.c_str()) != 0;  // never follow junctions
    bool ok = true;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(LongPath(JoinPath(p, "*")).c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring n = fd.cFileName;
            if (n == L"." || n == L"..") continue;
            std::string child = JoinPath(p, Narrow(n));
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                ok = RemoveTree(child) && ok;
            else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                ok = (RemoveDirectoryW(LongPath(child).c_str()) != 0) && ok;
            else
                ok = DeleteFileUtf8(child) && ok;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (attr & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(wp.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
    return RemoveDirectoryW(wp.c_str()) && ok;
}

uint64_t DirectorySize(const std::string& p) {
    uint64_t total = 0;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(LongPath(JoinPath(p, "*")).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            total += DirectorySize(JoinPath(p, Narrow(n)));
        else
            total += (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return total;
}

std::string LastErrorMessage(uint32_t code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    if (n == 0 || !buf) {
        // WinHTTP errors live in winhttp.dll's message table.
        HMODULE wh = GetModuleHandleW(L"winhttp.dll");
        if (wh)
            n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE |
                                   FORMAT_MESSAGE_IGNORE_INSERTS,
                               wh, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    }
    std::string msg;
    if (n && buf) msg = Trim(Narrow(std::wstring(buf, n)));
    if (buf) LocalFree(buf);
    char code_s[32];
    std::snprintf(code_s, sizeof code_s, "error %lu", static_cast<unsigned long>(code));
    return msg.empty() ? std::string(code_s) : msg + " (" + code_s + ")";
}

namespace {
HKEY HiveFor(const std::string& hive) {
    if (hive == "HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU") return HKEY_CURRENT_USER;
    return nullptr;
}
REGSAM ViewFlag(int view) {
    if (view == 64) return KEY_WOW64_64KEY;
    if (view == 32) return KEY_WOW64_32KEY;
    return 0;
}
}  // namespace

bool RegReadString(const std::string& hive, const std::string& subkey, const std::string& value, std::string& out,
                   int view) {
    HKEY root = HiveFor(hive);
    if (!root) return false;
    HKEY k;
    if (RegOpenKeyExW(root, Widen(subkey).c_str(), 0, KEY_QUERY_VALUE | ViewFlag(view), &k) != ERROR_SUCCESS)
        return false;
    std::wstring wv = Widen(value);
    DWORD type = 0, size = 0;
    LONG r = RegQueryValueExW(k, wv.c_str(), nullptr, &type, nullptr, &size);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || size > (1 << 20)) {
        RegCloseKey(k);
        return false;
    }
    std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
    r = RegQueryValueExW(k, wv.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&buf[0]), &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) return false;
    buf.resize(wcsnlen(buf.c_str(), buf.size()));
    out = Narrow(buf);
    return true;
}

bool RegReadDword(const std::string& hive, const std::string& subkey, const std::string& value, uint32_t& out,
                  int view) {
    HKEY root = HiveFor(hive);
    if (!root) return false;
    HKEY k;
    if (RegOpenKeyExW(root, Widen(subkey).c_str(), 0, KEY_QUERY_VALUE | ViewFlag(view), &k) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, data = 0, size = sizeof data;
    LONG r = RegQueryValueExW(k, Widen(value).c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&data), &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = data;
    return true;
}

bool RegKeyExists(const std::string& hive, const std::string& subkey, int view) {
    HKEY root = HiveFor(hive);
    if (!root) return false;
    HKEY k;
    if (RegOpenKeyExW(root, Widen(subkey).c_str(), 0, KEY_QUERY_VALUE | ViewFlag(view), &k) != ERROR_SUCCESS)
        return false;
    RegCloseKey(k);
    return true;
}

InstanceLock::~InstanceLock() {
    if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
}

bool InstanceLock::Acquire(const std::string& lockFile) {
    // An exclusively opened file is released by the OS if the process dies,
    // so a crash can never leave a stale lock behind.
    HANDLE h = CreateFileW(LongPath(lockFile).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    handle_ = h;
    return true;
}

namespace {
std::atomic<bool> g_cancel{false};
BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        // A second Ctrl+C falls through to the default handler (immediate exit);
        // interrupted transactions are detected and reported on the next run.
        if (g_cancel.exchange(true)) return FALSE;
        return TRUE;
    }
    return FALSE;
}
}  // namespace

void InstallCtrlHandler() { SetConsoleCtrlHandler(CtrlHandler, TRUE); }
bool CancelRequested() { return g_cancel.load(); }
void ResetCancel() { g_cancel = false; }
void RequestCancel() { g_cancel = true; }

}  // namespace sg
