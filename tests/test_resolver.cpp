#include "core/resolver.h"
#include "fixtures.h"
#include "test.h"
#include "util/error.h"

using namespace sg;

namespace {

Package Load(const std::string& id = "Example.Tool") {
    Package p;
    std::vector<std::string> errors;
    ParsePackage(ParseJson(sgtest::SampleManifestText(id)).value, p, errors);
    p.repository = "test";
    return p;
}

PlatformInfo Win7(Arch a) {
    PlatformInfo p;
    p.winMajor = 6;
    p.winMinor = 1;
    p.winBuild = 7601;
    p.nativeArch = a;
    return p;
}

PlatformInfo Win10(Arch a) {
    PlatformInfo p;
    p.winMajor = 10;
    p.winMinor = 0;
    p.winBuild = 19045;
    p.nativeArch = a;
    return p;
}

}  // namespace

TEST(resolver_never_picks_incompatible_newest_release) {
    Package p = Load();
    ResolveOptions o;
    ResolveResult r = ResolvePackage(p, Win7(Arch::X64), o);
    CHECK(r.ok);
    CHECK_EQ(r.candidate.release->version, std::string("1.5"));  // 2.0 needs NT 10.0
    CHECK(r.candidate.installer->type == InstallerType::Msi);     // msi preferred, x64 native
    CHECK(r.skipped.size() == 1);
    // On Windows 10 the newest release is selected.
    ResolveResult r10 = ResolvePackage(p, Win10(Arch::X64), o);
    CHECK(r10.ok && r10.candidate.release->version == "2.0");
}

TEST(resolver_explicit_version_incompatible_is_error) {
    Package p = Load();
    ResolveOptions o;
    o.version = "2.0";
    ResolveResult r = ResolvePackage(p, Win7(Arch::X64), o);
    CHECK(!r.ok);
    CHECK(r.errorCode == kExitIncompatible);
    o.version = "9.9";
    r = ResolvePackage(p, Win7(Arch::X64), o);
    CHECK(!r.ok && r.errorCode == kExitNotFound);
}

TEST(resolver_architecture_rules) {
    Package p = Load();
    ResolveOptions o;
    // 32-bit Windows 7 can only use the x86 exe.
    ResolveResult r = ResolvePackage(p, Win7(Arch::X86), o);
    CHECK(r.ok && r.candidate.installer->arch == Arch::X86 && r.candidate.installer->type == InstallerType::Exe);
    // Asking for x64 on 32-bit Windows fails.
    o.arch = Arch::X64;
    r = ResolvePackage(p, Win7(Arch::X86), o);
    CHECK(!r.ok);
    // x86 on 64-bit Windows is allowed when requested.
    o.arch = Arch::X86;
    r = ResolvePackage(p, Win7(Arch::X64), o);
    CHECK(r.ok && r.candidate.installer->arch == Arch::X86);
    CHECK(AcceptableArchs(Win7(Arch::X64), Arch::Unknown).front() == Arch::X64);
    // ARM64 Windows 10 (pre-22000) cannot emulate x64.
    PlatformInfo arm = Win10(Arch::Arm64);
    auto archs = AcceptableArchs(arm, Arch::Unknown);
    CHECK(archs.size() == 1 && archs[0] == Arch::X86);
}

TEST(resolver_scope_and_type_preference) {
    Package p = Load();
    ResolveOptions o;
    o.scopeSpecified = true;
    o.scope = Scope::User;
    ResolveResult r = ResolvePackage(p, Win7(Arch::X64), o);
    CHECK(r.ok && r.candidate.installer->type == InstallerType::Zip && r.candidate.scope == Scope::User);
    ResolveOptions o2;
    o2.typePreference = {InstallerType::Zip, InstallerType::Msi, InstallerType::Exe};
    r = ResolvePackage(p, Win7(Arch::X64), o2);
    CHECK(r.ok && r.candidate.installer->type == InstallerType::Zip && r.candidate.scope == Scope::User);
}

TEST(resolver_dependencies) {
    // app -> lib (>= 1.0) -> base ; base already installed.
    auto make = [](const std::string& id, const std::string& deps) {
        std::string text = sgtest::SampleManifestText(id);
        std::string from = "\"version\": \"1.5\",";
        text.replace(text.find(from), from.size(), "\"version\": \"1.5\", \"dependencies\": [" + deps + "],");
        Package p;
        std::vector<std::string> errors;
        ParsePackage(ParseJson(text).value, p, errors);
        if (!errors.empty()) ::sgtest::ReportFailure(__FILE__, __LINE__, errors.front());
        return p;
    };
    std::vector<Package> pkgs = {make("App", R"({"id": "Lib", "minVersion": "1.0"})"), make("Lib", R"({"id": "Base"})"),
                                 make("Base", "")};
    auto lookup = [&](const std::string& id) -> const Package* {
        for (const auto& p : pkgs)
            if (p.id == id) return &p;
        return nullptr;
    };
    ResolveOptions o;
    ResolveResult root = ResolvePackage(pkgs[0], Win7(Arch::X64), o);
    CHECK(root.ok);
    DependencyPlan plan = ResolveDependencies(root.candidate, Win7(Arch::X64), o, lookup,
                                              [](const std::string&) { return std::string(); });
    CHECK(plan.ok);
    CHECK(plan.steps.size() == 3);
    if (plan.steps.size() == 3) {
        CHECK_EQ(plan.steps[0].candidate.package->id, std::string("Base"));
        CHECK_EQ(plan.steps[1].candidate.package->id, std::string("Lib"));
        CHECK_EQ(plan.steps[2].candidate.package->id, std::string("App"));
        CHECK(plan.steps[0].dependency && !plan.steps[2].dependency);
    }
    // Installed Base satisfies the dependency.
    plan = ResolveDependencies(root.candidate, Win7(Arch::X64), o, lookup,
                               [](const std::string& id) { return id == "Base" ? std::string("1.0") : std::string(); });
    CHECK(plan.ok && plan.steps.size() == 2);
    // minVersion that cannot be met.
    pkgs[0] = make("App", R"({"id": "Lib", "minVersion": "5.0"})");
    root = ResolvePackage(pkgs[0], Win7(Arch::X64), o);
    plan = ResolveDependencies(root.candidate, Win7(Arch::X64), o, lookup, [](const std::string&) { return std::string(); });
    CHECK(!plan.ok && plan.errorCode == kExitIncompatible);
    // Missing dependency.
    pkgs[0] = make("App", R"({"id": "Missing"})");
    root = ResolvePackage(pkgs[0], Win7(Arch::X64), o);
    plan = ResolveDependencies(root.candidate, Win7(Arch::X64), o, lookup, [](const std::string&) { return std::string(); });
    CHECK(!plan.ok && plan.errorCode == kExitNotFound);
    // Cycle: Base -> App -> Lib -> Base
    pkgs[0] = make("App", R"({"id": "Lib"})");
    pkgs[2] = make("Base", R"({"id": "App"})");
    root = ResolvePackage(pkgs[0], Win7(Arch::X64), o);
    plan = ResolveDependencies(root.candidate, Win7(Arch::X64), o, lookup, [](const std::string&) { return std::string(); });
    CHECK(!plan.ok);
    CHECK(plan.error.find("cycle") != std::string::npos);
}
