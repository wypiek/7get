#include "util/version.h"

#include <vector>

#include "util/strings.h"

namespace sg {

bool IsValidVersionString(const std::string& v) {
    if (v.empty() || v.size() > 64) return false;
    auto alnum = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };
    if (!alnum(v[0])) return false;
    for (char c : v)
        if (!alnum(c) && c != '.' && c != '-' && c != '+') return false;
    return v.find("..") == std::string::npos;
}

namespace {

std::vector<std::string> Components(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&] { if (!cur.empty()) { out.push_back(cur); cur.clear(); } };
    for (char c : s) {
        bool digit = c >= '0' && c <= '9';
        if (c == '.' || c == '_') { flush(); continue; }
        // Split "1a" into "1","a" so "1.0a" orders sensibly.
        if (!cur.empty()) {
            bool curDigit = cur.back() >= '0' && cur.back() <= '9';
            if (curDigit != digit) flush();
        }
        cur += c;
    }
    flush();
    return out;
}

bool IsNumeric(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    return true;
}

int CompareNumeric(std::string a, std::string b) {
    a.erase(0, std::min(a.find_first_not_of('0'), a.size()));
    b.erase(0, std::min(b.find_first_not_of('0'), b.size()));
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    int c = a.compare(b);
    return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

int CompareComponentLists(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    size_t n = std::max(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        std::string x = i < a.size() ? a[i] : "0";
        std::string y = i < b.size() ? b[i] : "0";
        bool xn = IsNumeric(x), yn = IsNumeric(y);
        int c;
        if (xn && yn) c = CompareNumeric(x, y);
        else if (xn != yn) c = xn ? 1 : -1;  // "1.0.1" > "1.0.a"
        else {
            std::string lx = ToLowerAscii(x), ly = ToLowerAscii(y);
            c = lx < ly ? -1 : (lx > ly ? 1 : 0);
        }
        if (c) return c;
    }
    return 0;
}

}  // namespace

int CompareVersions(const std::string& a, const std::string& b) {
    auto strip = [](const std::string& s) { return s.substr(0, s.find('+')); };
    std::string sa = strip(a), sb = strip(b);
    size_t da = sa.find('-'), db = sb.find('-');
    std::string ra = sa.substr(0, da), rb = sb.substr(0, db);
    int c = CompareComponentLists(Components(ra), Components(rb));
    if (c) return c;
    bool pa = da != std::string::npos, pb = db != std::string::npos;
    if (pa != pb) return pa ? -1 : 1;  // pre-release < release
    if (!pa) return 0;
    return CompareComponentLists(Components(sa.substr(da + 1)), Components(sb.substr(db + 1)));
}

bool ParseWindowsVersion(const std::string& s, int& major, int& minor) {
    auto parts = Split(s, '.');
    if (parts.size() != 2) return false;
    int64_t a, b;
    if (!ParseInt64(parts[0], a) || !ParseInt64(parts[1], b)) return false;
    if (a < 5 || a > 99 || b < 0 || b > 99) return false;
    major = static_cast<int>(a);
    minor = static_cast<int>(b);
    return true;
}

int CompareWindowsVersion(int aMajor, int aMinor, int bMajor, int bMinor) {
    if (aMajor != bMajor) return aMajor < bMajor ? -1 : 1;
    if (aMinor != bMinor) return aMinor < bMinor ? -1 : 1;
    return 0;
}

}  // namespace sg
