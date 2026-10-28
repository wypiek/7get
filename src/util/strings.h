// SevenGet - string helpers (UTF-8 <-> UTF-16, formatting, parsing).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sg {

// Conversions between UTF-8 (internal representation) and UTF-16 (Win32 API).
// Invalid sequences are replaced with U+FFFD; these functions never throw.
std::wstring Widen(const std::string& utf8);
std::string Narrow(const std::wstring& utf16);

// Returns true if the byte sequence is well-formed UTF-8 (no overlongs, no surrogates).
bool IsValidUtf8(const std::string& s);

std::string ToLowerAscii(std::string s);
std::wstring ToLowerAsciiW(std::wstring s);
bool EqualsIgnoreCase(const std::string& a, const std::string& b);
bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle);
bool StartsWith(const std::string& s, const std::string& prefix);
bool EndsWith(const std::string& s, const std::string& suffix);
std::string Trim(const std::string& s);
std::vector<std::string> Split(const std::string& s, char sep);
std::string Join(const std::vector<std::string>& parts, const std::string& sep);

std::string HexEncode(const std::vector<uint8_t>& data, bool upper = false);
// Strict: even length, only [0-9a-fA-F]. Returns false on bad input.
bool HexDecode(const std::string& hex, std::vector<uint8_t>& out);

// "1.5 MiB", "820 KiB", "12 B"
std::string FormatBytes(uint64_t bytes);
// "1.2 MiB/s"
std::string FormatRate(double bytesPerSecond);
// "1m 05s"
std::string FormatDuration(double seconds);

// Parses a decimal integer; rejects trailing garbage and overflow.
bool ParseInt64(const std::string& s, int64_t& out);

// UTC timestamps in RFC 3339 form "YYYY-MM-DDTHH:MM:SSZ".
std::string FormatUtc(int64_t unixSeconds);
bool ParseUtc(const std::string& s, int64_t& unixSeconds);
int64_t NowUnix();

// Number of display columns a UTF-8 string occupies (approximation: one per code point,
// two for common CJK wide ranges). Used for table alignment.
size_t DisplayWidth(const std::string& utf8);

}  // namespace sg
