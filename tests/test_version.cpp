#include "test.h"
#include "util/strings.h"
#include "util/version.h"

using namespace sg;

TEST(version_ordering) {
    struct C { const char* a; const char* b; int expect; } cases[] = {
        {"24.09", "24.10", -1}, {"26.05", "23.01", 1}, {"0.83", "0.85", -1}, {"1.0", "1.0.0", 0},
        {"1.2.10", "1.2.9", 1}, {"1.0-beta1", "1.0", -1}, {"1.0-beta2", "1.0-beta10", -1},
        {"1.0+build5", "1.0", 0}, {"2.0a", "2.0b", -1}, {"10", "9", 1}, {"1.01", "1.1", 0},
        {"3.0.21", "3.0.3", 1}, {"1.0.1", "1.0.a", 1}, {"007", "7", 0},
    };
    for (const auto& c : cases) {
        int r = CompareVersions(c.a, c.b);
        int n = r < 0 ? -1 : r > 0 ? 1 : 0;
        if (n != c.expect)
            ::sgtest::ReportFailure(__FILE__, __LINE__, std::string(c.a) + " vs " + c.b + " gave " + std::to_string(n));
        int rr = CompareVersions(c.b, c.a);
        if ((rr < 0 ? -1 : rr > 0 ? 1 : 0) != -c.expect)
            ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("asymmetric ") + c.a + " " + c.b);
    }
}

TEST(version_string_validation) {
    CHECK(IsValidVersionString("26.05"));
    CHECK(IsValidVersionString("1.0-rc.1+abc"));
    CHECK(!IsValidVersionString(""));
    CHECK(!IsValidVersionString("../1"));
    CHECK(!IsValidVersionString("1..2"));
    CHECK(!IsValidVersionString("1.0 beta"));
    CHECK(!IsValidVersionString("1/2"));
    CHECK(!IsValidVersionString(".1"));
    CHECK(!IsValidVersionString(std::string(65, '1')));
}

TEST(windows_version_parsing) {
    int a, b;
    CHECK(ParseWindowsVersion("6.1", a, b) && a == 6 && b == 1);
    CHECK(ParseWindowsVersion("10.0", a, b) && a == 10 && b == 0);
    CHECK(!ParseWindowsVersion("6", a, b));
    CHECK(!ParseWindowsVersion("6.1.7601", a, b));
    CHECK(!ParseWindowsVersion("x.1", a, b));
    CHECK(CompareWindowsVersion(6, 1, 10, 0) < 0);
    CHECK(CompareWindowsVersion(6, 3, 6, 1) > 0);
}

TEST(strings_helpers) {
    int64_t t;
    CHECK(ParseUtc("2026-10-28T12:34:56Z", t));
    CHECK_EQ(FormatUtc(t), std::string("2026-10-28T12:34:56Z"));
    CHECK(ParseUtc("1970-01-01T00:00:00Z", t) && t == 0);
    CHECK(!ParseUtc("2026-02-30T00:00:00Z", t));
    CHECK(!ParseUtc("2026-10-28 12:34:56", t));
    CHECK_EQ(FormatBytes(512), std::string("512 B"));
    CHECK_EQ(FormatBytes(1536), std::string("1.5 KiB"));
    CHECK_EQ(FormatBytes(1663506), std::string("1.6 MiB"));
    int64_t v;
    CHECK(ParseInt64("-12", v) && v == -12);
    CHECK(!ParseInt64("12x", v));
    CHECK(!ParseInt64("99999999999999999999", v));
    std::string s = "\xC3\xA9t\xC3\xA9 \xE6\x97\xA5\xF0\x9F\x98\x80";
    CHECK_EQ(Narrow(Widen(s)), s);
    CHECK(DisplayWidth("\xE6\x97\xA5") == 2);
    std::vector<uint8_t> bytes;
    CHECK(HexDecode("00ffA0", bytes) && bytes.size() == 3 && bytes[1] == 0xff);
    CHECK(!HexDecode("0g", bytes));
    CHECK(!HexDecode("abc", bytes));
}
