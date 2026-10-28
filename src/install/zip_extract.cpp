#include "install/zip_extract.h"

#include <windows.h>

#include <cstring>

#include "miniz.h"
#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

namespace {

bool IsReservedDeviceName(const std::string& component) {
    std::string base = ToLowerAscii(component.substr(0, component.find('.')));
    static const char* names[] = {"con", "prn", "aux", "nul", "conin$", "conout$"};
    for (const char* n : names)
        if (base == n) return true;
    if (base.size() == 4 && (StartsWith(base, "com") || StartsWith(base, "lpt")) && base[3] >= '0' && base[3] <= '9')
        return true;
    return false;
}

}  // namespace

bool SanitizeZipEntryName(const std::string& name, std::string& rel, bool& isDir, std::string& why) {
    rel.clear();
    isDir = false;
    if (name.empty() || name.size() > 1024) { why = "empty or overlong name"; return false; }
    if (!IsValidUtf8(name)) { why = "name is not valid UTF-8"; return false; }
    std::string n = name;
    for (auto& c : n)
        if (c == '\\') c = '/';
    if (n[0] == '/') { why = "absolute path"; return false; }
    if (n.find(':') != std::string::npos) { why = "drive letter or alternate data stream"; return false; }
    for (unsigned char c : n)
        if (c < 0x20 || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            why = "invalid character in name";
            return false;
        }
    if (n.back() == '/') {
        isDir = true;
        n.pop_back();
        if (n.empty()) { why = "empty directory name"; return false; }
    }
    auto parts = Split(n, '/');
    std::vector<std::string> clean;
    for (const auto& p : parts) {
        if (p.empty()) { why = "empty path component"; return false; }
        if (p == "." || p == "..") { why = "relative path component '" + p + "'"; return false; }
        if (p.back() == '.' || p.back() == ' ') { why = "component ends with dot or space"; return false; }
        if (p.size() > 255) { why = "component too long"; return false; }
        if (IsReservedDeviceName(p)) { why = "reserved device name '" + p + "'"; return false; }
        clean.push_back(p);
    }
    rel = Join(clean, "\\");
    return true;
}

namespace {

struct WriteCtx {
    HANDLE file;
    uint64_t written = 0;
    uint64_t limit = 0;
    bool overflow = false;
};

size_t WriteCallback(void* opaque, mz_uint64 /*ofs*/, const void* buf, size_t n) {
    auto* ctx = static_cast<WriteCtx*>(opaque);
    if (CancelRequested()) return 0;
    if (ctx->written + n > ctx->limit) {
        ctx->overflow = true;
        return 0;
    }
    DWORD wrote = 0;
    if (!WriteFile(ctx->file, buf, static_cast<DWORD>(n), &wrote, nullptr) || wrote != n) return 0;
    ctx->written += n;
    return n;
}

// miniz reads the archive through this callback so non-ASCII paths work
// (its fopen-based helpers would use the ANSI code page).
size_t ReadCallback(void* opaque, mz_uint64 ofs, void* buf, size_t n) {
    HANDLE h = static_cast<HANDLE>(opaque);
    LARGE_INTEGER pos;
    pos.QuadPart = static_cast<LONGLONG>(ofs);
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN)) return 0;
    DWORD got = 0;
    if (!ReadFile(h, buf, static_cast<DWORD>(n), &got, nullptr)) return 0;
    return got;
}

}  // namespace

ZipResult ExtractZip(const std::string& zipPath, const std::string& destDir, const ZipLimits& limits) {
    ZipResult r;
    HANDLE zf = CreateFileW(Widen(zipPath).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (zf == INVALID_HANDLE_VALUE) {
        r.error = "cannot open archive: " + LastErrorMessage(GetLastError());
        return r;
    }
    LARGE_INTEGER size{};
    GetFileSizeEx(zf, &size);
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof zip);
    zip.m_pRead = ReadCallback;
    zip.m_pIO_opaque = zf;
    if (!mz_zip_reader_init(&zip, static_cast<mz_uint64>(size.QuadPart), 0)) {
        CloseHandle(zf);
        r.error = "not a valid ZIP archive";
        return r;
    }
    struct Closer {
        mz_zip_archive* z;
        HANDLE h;
        ~Closer() {
            mz_zip_reader_end(z);
            CloseHandle(h);
        }
    } closer{&zip, zf};

    mz_uint count = mz_zip_reader_get_num_files(&zip);
    if (count > limits.maxEntries) {
        r.error = "archive has too many entries";
        return r;
    }
    // Pass 1: validate everything before writing anything.
    uint64_t declaredTotal = 0;
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            r.error = "corrupt archive directory";
            return r;
        }
        std::string rel, why;
        bool isDir;
        if (!SanitizeZipEntryName(st.m_filename, rel, isDir, why)) {
            r.error = "unsafe archive entry '" + std::string(st.m_filename) + "': " + why;
            return r;
        }
        // Unix symlink (S_IFLNK) in external attributes.
        uint32_t unixMode = st.m_external_attr >> 16;
        if ((unixMode & 0170000) == 0120000) {
            r.error = "archive contains a symbolic link entry, which is not allowed";
            return r;
        }
        if (st.m_is_encrypted) {
            r.error = "encrypted archive entries are not supported";
            return r;
        }
        if (!st.m_is_supported) {
            r.error = "archive entry uses an unsupported compression method";
            return r;
        }
        declaredTotal += st.m_uncomp_size;
        if (declaredTotal > limits.maxTotalBytes) {
            r.error = "archive expands beyond the size limit";
            return r;
        }
        if (st.m_comp_size > 0 && static_cast<double>(st.m_uncomp_size) / static_cast<double>(st.m_comp_size) > limits.maxRatio &&
            st.m_uncomp_size > (1u << 20)) {
            r.error = "suspicious compression ratio (possible zip bomb)";
            return r;
        }
        std::string full = JoinPath(destDir, rel);
        if (!IsPathInside(destDir, full)) {
            r.error = "archive entry escapes the destination directory: " + std::string(st.m_filename);
            return r;
        }
    }
    // Pass 2: extract.
    for (mz_uint i = 0; i < count; ++i) {
        if (CancelRequested()) {
            r.error = "extraction cancelled";
            return r;
        }
        mz_zip_archive_file_stat st;
        mz_zip_reader_file_stat(&zip, i, &st);
        std::string rel, why;
        bool isDir;
        SanitizeZipEntryName(st.m_filename, rel, isDir, why);
        std::string full = JoinPath(destDir, rel);
        if (isDir) {
            if (!CreateDirectories(full)) {
                r.error = "cannot create directory " + full;
                return r;
            }
            continue;
        }
        if (!CreateDirectories(ParentPath(full))) {
            r.error = "cannot create directory " + ParentPath(full);
            return r;
        }
        if (FileExists(full)) {
            // Duplicate entry names (case-insensitively) would silently overwrite.
            r.error = "archive contains duplicate entry " + rel;
            return r;
        }
        std::wstring wfull = Widen(full);
        if (wfull.size() >= 240) wfull = L"\\\\?\\" + wfull;
        HANDLE out = CreateFileW(wfull.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE) {
            r.error = "cannot create " + full + ": " + LastErrorMessage(GetLastError());
            return r;
        }
        WriteCtx ctx{out, 0, st.m_uncomp_size, false};
        bool ok = mz_zip_reader_extract_to_callback(&zip, i, WriteCallback, &ctx, 0) != 0;
        FlushFileBuffers(out);
        CloseHandle(out);
        if (!ok || ctx.written != st.m_uncomp_size) {
            DeleteFileUtf8(full);
            r.error = CancelRequested() ? "extraction cancelled"
                      : ctx.overflow    ? "archive entry larger than declared: " + rel
                                        : "failed to extract " + rel + " (corrupt data or CRC mismatch)";
            return r;
        }
        r.totalBytes += ctx.written;
        r.files.push_back(rel);
    }
    r.ok = true;
    return r;
}

}  // namespace sg
