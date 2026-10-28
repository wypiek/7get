#include "util/log.h"

#include <windows.h>

#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

namespace {
std::string g_path;
const uint64_t kMaxLogBytes = 1 << 20;
}  // namespace

void Log::Init(const std::string& dir) {
    if (!CreateDirectories(dir)) return;
    g_path = JoinPath(dir, "sevenget.log");
    if (FileSize(g_path) > kMaxLogBytes) MoveFileReplace(g_path, g_path + ".1");
}

const std::string& Log::Path() { return g_path; }

void Log::Info(const std::string& m) { Write("INFO", m); }
void Log::Warn(const std::string& m) { Write("WARN", m); }
void Log::Error(const std::string& m) { Write("ERROR", m); }

void Log::Write(const char* level, const std::string& msg) {
    if (g_path.empty()) return;
    HANDLE h = CreateFileW(Widen(g_path).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string line = FormatUtc(NowUnix()) + " [" + std::to_string(GetCurrentProcessId()) + "] " + level + " " + msg;
    for (auto& c : line)
        if (c == '\n' || c == '\r') c = ' ';
    line += "\r\n";
    DWORD written = 0;
    WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(h);
}

}  // namespace sg
