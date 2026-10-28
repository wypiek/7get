// Minimal self-contained test framework (no external dependencies so the
// suite builds with the same toolchains as SevenGet and runs on Windows 7).
#pragma once

#include <cstdio>
#include <string>
#include <vector>

namespace sgtest {

struct TestCase {
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& Registry();
void ReportFailure(const char* file, int line, const std::string& what);
// Fresh empty directory for one test (inside the suite's temp root).
std::string TempDir(const std::string& name);
std::string DataPath(const std::string& name);

struct Registrar {
    Registrar(const char* n, void (*f)()) { Registry().push_back({n, f}); }
};

template <typename A, typename B>
std::string Describe(const A& a, const B& b) {
    return "values differ";
}
std::string Describe(const std::string& a, const std::string& b);
std::string Describe(long long a, long long b);

}  // namespace sgtest

#define TEST(name)                                                   \
    static void name();                                              \
    static ::sgtest::Registrar name##_registrar(#name, &name);       \
    static void name()

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) ::sgtest::ReportFailure(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define CHECK_EQ(a, b)                                                                                 \
    do {                                                                                               \
        auto&& _a = (a);                                                                               \
        auto&& _b = (b);                                                                               \
        if (!(_a == _b))                                                                               \
            ::sgtest::ReportFailure(__FILE__, __LINE__,                                                \
                                    "CHECK_EQ(" #a ", " #b "): " + ::sgtest::Describe(_a, _b));        \
    } while (0)
