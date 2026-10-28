// SevenGet - package version parsing and comparison.
//
// Versions are dot/dash separated sequences of components. Numeric components
// compare numerically ("24.09" < "24.10" < "26.05"), alphanumeric ones
// lexically (case-insensitive). A pre-release suffix introduced by '-'
// ("1.0-beta1") sorts before the plain release ("1.0"). Build metadata after
// '+' is ignored for ordering. Missing trailing numeric components are zero
// ("1.0" == "1.0.0").
#pragma once

#include <string>

namespace sg {

// Allowed characters: [0-9A-Za-z.+-], 1..64 chars, must start with an
// alphanumeric character, no "..".
bool IsValidVersionString(const std::string& v);

// Returns <0, 0, >0. Both inputs should satisfy IsValidVersionString.
int CompareVersions(const std::string& a, const std::string& b);

// "6.1" style Windows version strings. Returns false on malformed input.
bool ParseWindowsVersion(const std::string& s, int& major, int& minor);
int CompareWindowsVersion(int aMajor, int aMinor, int bMajor, int bMinor);

}  // namespace sg
