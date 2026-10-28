// SevenGet - safe ZIP extraction (miniz for inflate; all path handling here).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sg {

// Converts a ZIP entry name into a safe relative Windows path.
// Rejects: absolute paths, drive letters, UNC, ':' (alternate data streams),
// "." / ".." components, control characters, reserved DOS device names,
// components with trailing dots/spaces, and overlong names.
// isDir is set for entries ending in '/'.
bool SanitizeZipEntryName(const std::string& name, std::string& relPath, bool& isDir, std::string& why);

struct ZipLimits {
    uint64_t maxTotalBytes = 4ull << 30;
    uint32_t maxEntries = 100000;
    double maxRatio = 200.0;  // compressed:uncompressed ratio guard against zip bombs
};

struct ZipResult {
    bool ok = false;
    std::string error;
    std::vector<std::string> files;  // relative paths of extracted files
    uint64_t totalBytes = 0;
};

// Extracts zipPath into destDir (which must exist and be empty). Every
// resulting path is re-checked to be inside destDir. Symlink entries are
// rejected. Cancels on Ctrl+C.
ZipResult ExtractZip(const std::string& zipPath, const std::string& destDir, const ZipLimits& limits = {});

}  // namespace sg
