// Test runner. Usage: sevenget_tests [filter]
// Also acts as a helper child process for process tests:
//   sevenget_tests --child-exit <code> [args...]  writes its argv to
//   %SEVENGET_CHILD_OUT% (one per line, UTF-8) and exits with <code>.
#include <windows.h>

#include <cstdlib>
#include <string>

#include "platform/winutil.h"
#include "test.h"
#include "util/strings.h"

namespace sgtest {

namespace {
int g_failures = 0;
std::string g_root;
}  // namespace

std::vector<TestCase>& Registry() {
    static std::vector<TestCase> r;
    return r;
}

void ReportFailure(const char* file, int line, const std::string& what) {
    ++g_failures;
    std::fprintf(stdout, "    FAILED %s:%d: %s\n", file, line, what.c_str());
}

std::string Describe(const std::string& a, const std::string& b) { return "\"" + a + "\" vs \"" + b + "\""; }
std::string Describe(long long a, long long b) { return std::to_string(a) + " vs " + std::to_string(b); }

std::string TempDir(const std::string& name) {
    std::string d = sg::JoinPath(g_root, name);
    sg::RemoveTree(d);
    sg::CreateDirectories(d);
    return d;
}

std::string DataPath(const std::string& name) {
#ifdef SEVENGET_TEST_DATA
    std::string env = sg::GetEnv("SEVENGET_TEST_DATA");
    std::string base = env.empty() ? SEVENGET_TEST_DATA : env;
#else
    std::string base = sg::GetEnv("SEVENGET_TEST_DATA");
#endif
    // Accept forward slashes from CMake paths.
    for (auto& c : base)
        if (c == '/') c = '\\';
    return sg::JoinPath(base, name);
}

}  // namespace sgtest

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(sg::Narrow(argv[i]));
    if (!args.empty() && args[0] == "--child-exit") {
        std::string out = sg::GetEnv("SEVENGET_CHILD_OUT");
        std::string text;
        for (size_t i = 2; i < args.size(); ++i) text += args[i] + "\n";
        if (!out.empty()) sg::WriteFileAtomic(out, text);
        return args.size() > 1 ? std::atoi(args[1].c_str()) : 0;
    }
    // Isolated state directory for the whole run.
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    sgtest::g_root = sg::JoinPath(sg::Narrow(tmp), "sevenget-tests-" + std::to_string(GetCurrentProcessId()));
    sg::RemoveTree(sgtest::g_root);
    sg::CreateDirectories(sgtest::g_root);
    std::string home = sg::JoinPath(sgtest::g_root, "home \xC3\xA9\xE6\x97\xA5");  // spaces + non-ASCII
    sg::CreateDirectories(home);
    SetEnvironmentVariableW(L"SEVENGET_HOME", sg::Widen(home).c_str());

    std::string filter = args.empty() ? "" : args[0];
    int run = 0, failedTests = 0;
    for (const auto& t : sgtest::Registry()) {
        if (!filter.empty() && std::string(t.name).find(filter) == std::string::npos) continue;
        int before = sgtest::g_failures;
        std::fprintf(stdout, "[ RUN  ] %s\n", t.name);
        std::fflush(stdout);
        try {
            t.fn();
        } catch (const std::exception& e) {
            sgtest::ReportFailure(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        } catch (...) {
            sgtest::ReportFailure(__FILE__, __LINE__, "unexpected non-std exception");
        }
        ++run;
        bool ok = sgtest::g_failures == before;
        if (!ok) ++failedTests;
        std::fprintf(stdout, "[ %s ] %s\n", ok ? " OK " : "FAIL", t.name);
        std::fflush(stdout);
    }
    std::fprintf(stdout, "\n%d tests, %d passed, %d failed (%d failed checks)\n", run, run - failedTests, failedTests,
                 sgtest::g_failures);
    sg::RemoveTree(sgtest::g_root);
    return failedTests ? 1 : 0;
}
