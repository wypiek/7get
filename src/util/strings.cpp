#include "util/strings.h"

#include <cstdio>
#include <ctime>
#include <limits>

namespace sg {

namespace {

// Decodes one code point from UTF-8; returns false on malformed input.
bool DecodeUtf8(const std::string& s, size_t& i, uint32_t& cp) {
    const auto b = [&](size_t k) { return static_cast<uint8_t>(s[k]); };
    uint8_t c = b(i);
    if (c < 0x80) { cp = c; i += 1; return true; }
    size_t len;
    uint32_t min;
    if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
    else return false;
    if (i + len > s.size()) return false;
    for (size_t k = 1; k < len; ++k) {
        uint8_t cc = b(i + k);
        if ((cc & 0xC0) != 0x80) return false;
        cp = (cp << 6) | (cc & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
    i += len;
    return true;
}

void AppendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out += static_cast<char>(cp);
    else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

}  // namespace

std::wstring Widen(const std::string& utf8) {
    std::wstring out;
    out.reserve(utf8.size());
    size_t i = 0;
    while (i < utf8.size()) {
        uint32_t cp;
        if (!DecodeUtf8(utf8, i, cp)) { cp = 0xFFFD; ++i; }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out += static_cast<wchar_t>(0xD800 + (cp >> 10));
            out += static_cast<wchar_t>(0xDC00 + (cp & 0x3FF));
        } else {
            out += static_cast<wchar_t>(cp);
        }
    }
    return out;
}

std::string Narrow(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (size_t i = 0; i < w.size(); ++i) {
        uint32_t c = static_cast<uint16_t>(w[i]);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < w.size()) {
            uint32_t d = static_cast<uint16_t>(w[i + 1]);
            if (d >= 0xDC00 && d <= 0xDFFF) {
                AppendUtf8(out, 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00));
                ++i;
                continue;
            }
        }
        if (c >= 0xD800 && c <= 0xDFFF) c = 0xFFFD;
        AppendUtf8(out, c);
    }
    return out;
}

bool IsValidUtf8(const std::string& s) {
    size_t i = 0;
    uint32_t cp;
    while (i < s.size())
        if (!DecodeUtf8(s, i, cp)) return false;
    return true;
}

std::string ToLowerAscii(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::wstring ToLowerAsciiW(std::wstring s) {
    for (auto& c : s)
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    return s;
}

bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    return ToLowerAscii(a) == ToLowerAscii(b);
}

bool ContainsIgnoreCase(const std::string& h, const std::string& n) {
    return ToLowerAscii(h).find(ToLowerAscii(n)) != std::string::npos;
}

bool StartsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool EndsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> Split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

std::string Join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string HexEncode(const std::vector<uint8_t>& data, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out += digits[b >> 4];
        out += digits[b & 15];
    }
    return out;
}

bool HexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int h = val(hex[i]), l = val(hex[i + 1]);
        if (h < 0 || l < 0) return false;
        out.push_back(static_cast<uint8_t>(h * 16 + l));
    }
    return true;
}

std::string FormatBytes(uint64_t bytes) {
    static const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }
    char buf[32];
    if (u == 0) std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(bytes));
    else std::snprintf(buf, sizeof buf, v >= 100 ? "%.0f %s" : "%.1f %s", v, units[u]);
    return buf;
}

std::string FormatRate(double bps) {
    if (bps < 0) bps = 0;
    return FormatBytes(static_cast<uint64_t>(bps)) + "/s";
}

std::string FormatDuration(double seconds) {
    if (seconds < 0) seconds = 0;
    long long s = static_cast<long long>(seconds + 0.5);
    char buf[32];
    if (s >= 3600) std::snprintf(buf, sizeof buf, "%lldh %02lldm", s / 3600, (s / 60) % 60);
    else if (s >= 60) std::snprintf(buf, sizeof buf, "%lldm %02llds", s / 60, s % 60);
    else std::snprintf(buf, sizeof buf, "%llds", s);
    return buf;
}

bool ParseInt64(const std::string& s, int64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') { neg = true; i = 1; if (s.size() == 1) return false; }
    uint64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        uint64_t d = static_cast<uint64_t>(s[i] - '0');
        if (v > (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - d) / 10) return false;
        v = v * 10 + d;
    }
    out = neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
    return true;
}

namespace {
// Days from civil date (Howard Hinnant's algorithm), independent of the C runtime's timegm.
int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void CivilFromDays(int64_t z, int64_t& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
}
}  // namespace

std::string FormatUtc(int64_t t) {
    int64_t days = t / 86400;
    int64_t rem = t % 86400;
    if (rem < 0) { rem += 86400; --days; }
    int64_t y; unsigned m, d;
    CivilFromDays(days, y, m, d);
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02d:%02d:%02dZ", static_cast<long long>(y), m, d,
                  static_cast<int>(rem / 3600), static_cast<int>((rem / 60) % 60), static_cast<int>(rem % 60));
    return buf;
}

bool ParseUtc(const std::string& s, int64_t& out) {
    // Accept exactly YYYY-MM-DDTHH:MM:SSZ
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z')
        return false;
    auto num = [&](size_t pos, size_t len, int& v) {
        v = 0;
        for (size_t i = pos; i < pos + len; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            v = v * 10 + (s[i] - '0');
        }
        return true;
    };
    int Y, M, D, h, mi, se;
    if (!num(0, 4, Y) || !num(5, 2, M) || !num(8, 2, D) || !num(11, 2, h) || !num(14, 2, mi) || !num(17, 2, se))
        return false;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || mi > 59 || se > 60) return false;
    static const int mdays[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (D > mdays[M - 1]) return false;
    out = DaysFromCivil(Y, static_cast<unsigned>(M), static_cast<unsigned>(D)) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

int64_t NowUnix() { return static_cast<int64_t>(std::time(nullptr)); }

size_t DisplayWidth(const std::string& s) {
    size_t w = 0, i = 0;
    while (i < s.size()) {
        uint32_t cp;
        if (!DecodeUtf8(s, i, cp)) { ++i; ++w; continue; }
        if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
            (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6))
            w += 2;
        else if (cp >= 0x0300 && cp <= 0x036F)
            ;  // combining marks
        else
            w += 1;
    }
    return w;
}

}  // namespace sg
