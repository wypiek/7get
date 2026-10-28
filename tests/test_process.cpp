#include <windows.h>
#include <shellapi.h>

#include <iterator>

#include "install/backend.h"
#include "platform/process.h"
#include "platform/winutil.h"
#include "test.h"
#include "util/strings.h"

using namespace sg;

namespace {
const char* kTricky[] = {
    "simple",
    "with space",
    "",
    "trailing\\",
    "trailing space\\",
    "quote\"inside",
    "\"quoted\"",
    "back\\\\slashes\\\\",
    "back\\\"quote",
    "C:\\Program Files\\App Dir\\",
    "& calc.exe",
    "| more > out.txt",
    "%PATH% ^ !x!",
    "\xC3\xA9t\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC",
    "tab\there",
};
}  // namespace

TEST(quote_argument_roundtrips_through_CommandLineToArgvW) {
    std::vector<std::string> args(std::begin(kTricky), std::end(kTricky));
    std::string cmd = BuildCommandLine("C:\\dir with space\\app.exe", args);
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(Widen(cmd).c_str(), &argc);
    CHECK(argv != nullptr);
    CHECK_EQ(argc, static_cast<int>(args.size() + 1));
    if (argv && argc == static_cast<int>(args.size() + 1)) {
        CHECK_EQ(Narrow(argv[0]), std::string("C:\\dir with space\\app.exe"));
        for (size_t i = 0; i < args.size(); ++i) CHECK_EQ(Narrow(argv[i + 1]), args[i]);
    }
    LocalFree(argv);
    // Our own splitter (used for UninstallString) agrees.
    auto split = SplitCommandLine(cmd);
    CHECK(split.size() == args.size() + 1);
    for (size_t i = 0; i < args.size() && i + 1 < split.size(); ++i) CHECK_EQ(split[i + 1], args[i]);
}

TEST(split_uninstall_strings) {
    auto a = SplitCommandLine("\"C:\\Program Files\\7-Zip\\Uninstall.exe\" /S");
    CHECK(a.size() == 2 && a[0] == "C:\\Program Files\\7-Zip\\Uninstall.exe" && a[1] == "/S");
    a = SplitCommandLine("MsiExec.exe /X{23170F69-40C1-2702-2605-000001000000}");
    CHECK(a.size() == 2 && a[0] == "MsiExec.exe");
    a = SplitCommandLine("C:\\NoQuotes\\un.exe");
    CHECK(a.size() == 1);
}

TEST(msi_property_quoting) {
    CHECK_EQ(MsiPropertyArg("INSTALLDIR", "C:\\Program Files\\X"), std::string("INSTALLDIR=\"C:\\Program Files\\X\""));
    CHECK_EQ(MsiPropertyArg("P", "a\"b"), std::string("P=\"a\"\"b\""));
}

TEST(run_process_passes_arguments_and_exit_codes) {
    std::string dir = sgtest::TempDir("proc \xC3\xA9");
    std::string outFile = JoinPath(dir, "child out.txt");
    SetEnvironmentVariableW(L"SEVENGET_CHILD_OUT", Widen(outFile).c_str());
    std::vector<std::string> args = {"--child-exit", "42"};
    for (const char* t : kTricky)
        if (*t) args.push_back(t);  // empty args are covered by the CommandLineToArgvW test
    ProcessResult r = RunProcess(GetExecutablePath(), args, Elevation::Never, dir);
    CHECK(r.started);
    CHECK_EQ(static_cast<long long>(r.exitCode), 42LL);
    std::string text;
    CHECK(ReadFileBytes(outFile, text));
    auto lines = Split(text, '\n');
    size_t idx = 0;
    for (const char* t : kTricky) {
        if (!*t) continue;
        if (idx < lines.size()) CHECK_EQ(lines[idx], std::string(t));
        ++idx;
    }
    ProcessResult missing = RunProcess(JoinPath(dir, "does-not-exist.exe"), {}, Elevation::Never);
    CHECK(!missing.started && missing.startError != 0);
    SetEnvironmentVariableW(L"SEVENGET_CHILD_OUT", nullptr);
}

TEST(installer_exit_code_classification) {
    std::vector<int64_t> ok = {0}, reboot = {3010, 1641};
    CHECK(ClassifyExitCode(0, ok, reboot) == BackendResult::Status::Success);
    CHECK(ClassifyExitCode(3010, ok, reboot) == BackendResult::Status::RebootRequired);
    CHECK(ClassifyExitCode(1602, ok, reboot) == BackendResult::Status::Cancelled);
    CHECK(ClassifyExitCode(1618, ok, reboot) == BackendResult::Status::Busy);
    CHECK(ClassifyExitCode(1603, ok, reboot) == BackendResult::Status::Failed);
    CHECK(ClassifyExitCode(0xC0000005u, ok, reboot) == BackendResult::Status::Failed);
    CHECK(ClassifyExitCode(1, {0, 1}, {}) == BackendResult::Status::Success);  // manifest-declared success
    CHECK(DescribeInstallerExitCode(1618).find("already in progress") != std::string::npos);
    CHECK(IsForbiddenUninstallHost("C:\\Windows\\System32\\cmd.exe"));
    CHECK(IsForbiddenUninstallHost("c:\\windows\\system32\\RUNDLL32.EXE"));
    CHECK(!IsForbiddenUninstallHost("C:\\Program Files\\7-Zip\\Uninstall.exe"));
}
