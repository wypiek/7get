#include "core/manifest.h"
#include "fixtures.h"
#include "test.h"
#include "util/strings.h"

using namespace sg;

namespace {

bool ParseText(const std::string& text, Package& p, std::vector<std::string>& errors) {
    auto r = ParseJson(text);
    if (!r.ok) {
        errors.push_back(r.error);
        return false;
    }
    return ParsePackage(r.value, p, errors);
}

// Applies a textual replacement to the sample manifest and expects rejection.
void ExpectRejected(const std::string& from, const std::string& to, const char* line) {
    std::string text = sgtest::SampleManifestText();
    size_t pos = text.find(from);
    if (pos == std::string::npos) {
        ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("fixture text not found: ") + from);
        return;
    }
    text.replace(pos, from.size(), to);
    Package p;
    std::vector<std::string> errors;
    if (ParseText(text, p, errors) || errors.empty())
        ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("accepted invalid manifest: ") + line);
}

}  // namespace

TEST(manifest_valid_sample_parses) {
    Package p;
    std::vector<std::string> errors;
    CHECK(ParseText(sgtest::SampleManifestText(), p, errors));
    CHECK(errors.empty());
    CHECK_EQ(p.id, std::string("Example.Tool"));
    CHECK(p.releases.size() == 2);
    const Installer& msi = p.releases[1].installers[0];
    CHECK(msi.type == InstallerType::Msi);
    CHECK(msi.rebootExitCodes.size() == 2);  // msi default 3010, 1641
    CHECK(msi.upgradeBehavior == "uninstall-first");
    CHECK(p.releases[1].installers[1].upgradeBehavior == "install-over");
    CHECK(p.releases[1].installers[2].SupportsScope(Scope::User));
    // JSON round trip keeps it valid.
    Package q;
    errors.clear();
    CHECK(ParsePackage(PackageToJson(p), q, errors));
}

TEST(manifest_rejects_malicious_or_malformed_fields) {
    ExpectRejected("\"Example.Tool\"", "\"../../evil\"", "path traversal id");
    ExpectRejected("\"Example.Tool\"", "\"CON\"", "reserved device id");
    ExpectRejected("\"Example.Tool\"", "\"a b\"", "space in id");
    ExpectRejected("https://example.invalid/tool-1.5.exe", "http://example.invalid/tool-1.5.exe", "plain http");
    ExpectRejected("https://example.invalid/tool-1.5.exe", "file:///C:/x.exe", "file url");
    ExpectRejected("3333333333333333333333333333333333333333333333333333333333333333", "33", "short sha");
    ExpectRejected("\"minWindows\": \"6.1\", \"scope\": [\"machine\"], \"silentArgs\": [\"/S\", \"/NORESTART\"]",
                   "\"minWindows\": \"6.1\", \"scope\": [\"machine\"], \"silentArgs\": []", "exe without silent args");
    ExpectRejected("\"/NORESTART\"", "\"/D=\\\"C:\\\\x\\\" & calc\"", "quote in argument");
    ExpectRejected("\"/NORESTART\"", "\"a\\u0001b\"", "control char in argument");
    ExpectRejected("\"registryKey\": \"ExampleTool\"}", "\"registryKey\": \"..\\\\Run\"}", "registry key traversal");
    ExpectRejected("\"uninstall\": {\"strategy\": \"msi\"}", "\"uninstall\": {\"strategy\": \"files\"}", "wrong strategy");
    ExpectRejected("\"minWindows\": \"10.0\"", "\"minWindows\": \"ten\"", "bad windows version");
    ExpectRejected("\"version\": \"1.5\"", "\"version\": \"2.0\"", "duplicate version");
    ExpectRejected("\"version\": \"1.5\"", "\"version\": \"../1.5\"", "path in version");
    ExpectRejected("\"license\": \"MIT\",", "\"license\": \"MIT\", \"postInstallScript\": \"evil.cmd\",", "unknown field");
    ExpectRejected("\"files\": [\"tool.exe\"]", "\"files\": []", "required zip signature without files");
    ExpectRejected("\"files\": [\"tool.exe\"]", "\"files\": [\"../tool.exe\"]", "signed file traversal");
    ExpectRejected("\"arch\": \"x86\"", "\"arch\": \"mips\"", "unknown arch");
    ExpectRejected("\"type\": \"zip\"", "\"type\": \"cmd\"", "unknown type");
    ExpectRejected("\"scope\": [\"user\", \"machine\"]", "\"scope\": [\"everyone\"]", "bad scope");
}

TEST(manifest_msi_property_rules) {
    std::string text = sgtest::SampleManifestText();
    std::string from = "\"minWindows\": \"6.1\", \"scope\": [\"machine\"], \"uninstall\": {\"strategy\": \"msi\"}";
    auto withArgs = [&](const std::string& args) {
        std::string t = text;
        t.replace(t.find(from), from.size(),
                  "\"minWindows\": \"6.1\", \"scope\": [\"machine\"], \"silentArgs\": [" + args +
                      "], \"uninstall\": {\"strategy\": \"msi\"}");
        Package p;
        std::vector<std::string> errors;
        return ParseText(t, p, errors);
    };
    CHECK(withArgs("\"INSTALLDESKTOPSHORTCUT=0\""));
    CHECK(!withArgs("\"/i\""));
    CHECK(!withArgs("\"TRANSFORMS=evil.mst\""));
    CHECK(!withArgs("\"lowercase=1\""));
    CHECK(!withArgs("\"REBOOT=Force\""));
}

TEST(manifest_identifier_helpers) {
    CHECK(IsValidPackageId("7zip.7zip"));
    CHECK(IsValidPackageId("SimonTatham.PuTTY"));
    CHECK(!IsValidPackageId("nul"));
    CHECK(!IsValidPackageId("Lpt1.x"));
    CHECK(!IsValidPackageId("a..b"));
    CHECK(!IsValidPackageId(".hidden"));
    CHECK(!IsValidPackageId("x\\y"));
    CHECK(IsValidGuid("{23170F69-40C1-2702-2605-000001000000}"));
    CHECK(!IsValidGuid("23170F69-40C1-2702-2605-000001000000"));
    CHECK(!IsValidGuid("{23170F69-40C1-2702-2605-00000100000Z}"));
    CHECK(IsSafeArgument("/D=C:\\Program Files\\x"));
    CHECK(!IsSafeArgument("a\"b"));
    CHECK(!IsSafeArgument(""));
}
