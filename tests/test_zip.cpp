#include "install/zip_extract.h"
#include "platform/winutil.h"
#include "test.h"

using namespace sg;

TEST(zip_entry_name_sanitizer) {
    std::string rel, why;
    bool dir;
    CHECK(SanitizeZipEntryName("app/sub/file.txt", rel, dir, why) && rel == "app\\sub\\file.txt" && !dir);
    CHECK(SanitizeZipEntryName("app/", rel, dir, why) && dir && rel == "app");
    const char* bad[] = {"../x", "a/../../x", "/abs", "\\abs", "C:/x", "C:x", "a\\..\\..\\x", "x:ads", "a/./b",
                         "CON", "dir/nul.txt", "com1", "LPT9.log", "trailing.", "trailing ", "a//b", "", "a\x01" "b",
                         "wild*card", "aux.tar.gz"};
    for (const char* b : bad)
        if (SanitizeZipEntryName(b, rel, dir, why))
            ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("accepted: ") + b);
}

TEST(zip_extracts_good_archive_with_unicode_names) {
    std::string dest = sgtest::TempDir("zip good \xC3\xA9");
    ZipResult r = ExtractZip(sgtest::DataPath("good.zip"), dest);
    CHECK(r.ok);
    CHECK(r.files.size() == 3);
    CHECK(FileExists(JoinPath(dest, "app\\tool.exe")));
    CHECK(FileExists(JoinPath(dest, "app\\readme \xC3\xA9\xE6\x97\xA5.txt")));
    CHECK(FileExists(JoinPath(dest, "app\\sub\\dir\\config.ini")));
}

TEST(zip_slip_and_hostile_archives_rejected) {
    const char* hostile[] = {"slip-dotdot.zip", "slip-nested.zip", "slip-absolute.zip", "slip-drive.zip",
                             "slip-backslash.zip", "slip-ads.zip", "slip-device.zip", "slip-symlink.zip",
                             "dup-case.zip", "not-a-zip.zip", "truncated.zip"};
    std::string root = sgtest::TempDir("zip hostile");
    for (const char* h : hostile) {
        std::string dest = JoinPath(root, h);
        CreateDirectories(dest);
        ZipResult r = ExtractZip(sgtest::DataPath(h), dest);
        if (r.ok) ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("extracted hostile archive ") + h);
        // Nothing may be written outside the destination.
        CHECK(!FileExists(JoinPath(root, "evil.txt")));
    }
    // Validation happens before any file is written for path attacks.
    CHECK(!FileExists(JoinPath(JoinPath(root, "slip-dotdot.zip"), "ok.txt")));
}

TEST(path_containment_helper) {
    CHECK(IsPathInside("C:\\apps", "C:\\apps\\x\\y.exe"));
    CHECK(IsPathInside("C:\\apps\\", "c:\\APPS\\x"));
    CHECK(!IsPathInside("C:\\apps", "C:\\apps2\\x"));
    CHECK(!IsPathInside("C:\\apps", "C:\\apps\\..\\Windows\\x"));
    CHECK(!IsPathInside("C:\\apps", "D:\\apps\\x"));
}
