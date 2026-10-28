// sevenget-repotool - create keys, validate manifests, build and sign
// repository indexes. Runs on Windows (uses CNG like the client).
// A Python equivalent for Linux/macOS hosts is tools/repotool.py.
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "core/manifest.h"
#include "core/repository.h"
#include "platform/crypto.h"
#include "platform/winutil.h"
#include "util/json.h"
#include "util/strings.h"

using namespace sg;

namespace {

void Print(const std::string& s) {
    std::string out = s + "\n";
    DWORD w;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(h, &mode)) {
        std::wstring ws = Widen(out);
        WriteConsoleW(h, ws.c_str(), static_cast<DWORD>(ws.size()), &w, nullptr);
    } else {
        WriteFile(h, out.data(), static_cast<DWORD>(out.size()), &w, nullptr);
    }
}

int Fail(const std::string& s) {
    std::string out = "error: " + s + "\n";
    DWORD w;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), out.data(), static_cast<DWORD>(out.size()), &w, nullptr);
    return 1;
}

std::string Opt(std::vector<std::string>& args, const std::string& name, const std::string& def = {}) {
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == name) {
            std::string v = args[i + 1];
            args.erase(args.begin() + static_cast<long>(i), args.begin() + static_cast<long>(i) + 2);
            return v;
        }
    return def;
}

int Usage() {
    Print("sevenget-repotool - SevenGet repository maintenance\n"
          "\n"
          "  keygen --private <file> --public <file>\n"
          "  lint <manifest.json>...\n"
          "  build --manifests <dir> --name <repo> --key <private> --out <dir>\n"
          "        [--sequence <n>] [--expires-days <days>]\n"
          "  verify --public <key.pub> <repo-dir>\n"
          "  fingerprint <key.pub>\n"
          "  hash <file>");
    return 2;
}

bool LoadPrivate(const std::string& path, PrivateKey& k, std::string& err) {
    std::string text;
    if (!ReadFileBytes(path, text, 4096)) {
        err = "cannot read " + path;
        return false;
    }
    return ParsePrivateKey(text, k, err);
}

int CmdKeygen(std::vector<std::string> a) {
    std::string priv = Opt(a, "--private"), pub = Opt(a, "--public");
    if (priv.empty() || pub.empty()) return Usage();
    if (FileExists(priv)) return Fail(priv + " exists; refusing to overwrite a private key");
    PrivateKey k;
    PublicKey p;
    std::string err;
    if (!GenerateKeyPair(k, p, err)) return Fail(err);
    if (!WriteFileAtomic(priv, FormatPrivateKey(k) + "\n") || !WriteFileAtomic(pub, FormatPublicKey(p) + "\n"))
        return Fail("cannot write key files");
    Print("private key: " + priv + "  (keep this offline; anyone with it can publish packages)");
    Print("public key:  " + pub);
    Print("fingerprint: " + p.FingerprintDisplay());
    return 0;
}

int CmdLint(const std::vector<std::string>& files) {
    if (files.empty()) return Usage();
    int bad = 0;
    for (const auto& f : files) {
        std::string text;
        if (!ReadFileBytes(f, text)) {
            ++bad;
            Fail("cannot read " + f);
            continue;
        }
        auto pr = ParseJson(text);
        Package p;
        std::vector<std::string> errors;
        if (!pr.ok) errors.push_back(pr.error);
        else ParsePackage(pr.value, p, errors);
        if (errors.empty()) {
            Print("OK    " + f);
        } else {
            ++bad;
            Print("FAIL  " + f);
            for (const auto& e : errors) Print("      " + e);
        }
    }
    return bad ? 1 : 0;
}

int CmdBuild(std::vector<std::string> a) {
    std::string dir = Opt(a, "--manifests"), name = Opt(a, "--name"), keyPath = Opt(a, "--key"), out = Opt(a, "--out");
    std::string seqS = Opt(a, "--sequence"), daysS = Opt(a, "--expires-days", "180");
    if (dir.empty() || name.empty() || keyPath.empty() || out.empty()) return Usage();
    if (!IsValidRepoName(name)) return Fail("invalid repository name");
    PrivateKey key;
    std::string err;
    if (!LoadPrivate(keyPath, key, err)) return Fail(err);
    PublicKey pub = PublicFromPrivate(key);

    int64_t days = 0, sequence = 0;
    if (!ParseInt64(daysS, days) || days < 1 || days > 730) return Fail("--expires-days must be 1..730");
    std::string existing;
    if (seqS.empty()) {
        sequence = 1;
        if (ReadFileBytes(JoinPath(out, "index.json"), existing)) {
            auto pr = ParseJson(existing);
            const Json* s = pr.ok ? pr.value.Find("sequence") : nullptr;
            if (s && s->IsInteger()) sequence = s->AsInt() + 1;
        }
    } else if (!ParseInt64(seqS, sequence) || sequence < 1) {
        return Fail("--sequence must be a positive integer");
    }

    std::vector<std::string> names = ListDirectory(dir);
    std::sort(names.begin(), names.end());
    Json pkgs = Json::Array();
    int bad = 0;
    for (const auto& n : names) {
        if (!EndsWith(ToLowerAscii(n), ".json")) continue;
        std::string text;
        ReadFileBytes(JoinPath(dir, n), text);
        auto pr = ParseJson(text);
        Package p;
        std::vector<std::string> errors;
        if (!pr.ok) errors.push_back(pr.error);
        else ParsePackage(pr.value, p, errors);
        if (!errors.empty()) {
            ++bad;
            Print("FAIL  " + n);
            for (const auto& e : errors) Print("      " + e);
            continue;
        }
        pkgs.Push(pr.value);
    }
    if (bad) return Fail(std::to_string(bad) + " manifest(s) invalid; index not written");
    int64_t now = NowUnix();
    Json idx = Json::Object();
    idx.Set("schema", 1);
    idx.Set("repository", name);
    idx.Set("sequence", sequence);
    idx.Set("generated", FormatUtc(now));
    idx.Set("expires", FormatUtc(now + days * 86400));
    idx.Set("packages", pkgs);
    std::string indexText = idx.Dump(true) + "\n";
    Bytes sig;
    if (!SignEcdsaP256(key, indexText, sig, err)) return Fail(err);
    // Self-check before publishing.
    IndexPolicy pol;
    pol.now = now;
    IndexCheck chk = VerifyIndex(indexText, FormatSignatureFile(pub, sig), pub, pol);
    if (!chk.ok) return Fail("self-verification failed: " + chk.error);
    CreateDirectories(out);
    if (!WriteFileAtomic(JoinPath(out, "index.json"), indexText) ||
        !WriteFileAtomic(JoinPath(out, "index.json.sig"), FormatSignatureFile(pub, sig)) ||
        !WriteFileAtomic(JoinPath(out, "key.pub"), FormatPublicKey(pub) + "\n"))
        return Fail("cannot write repository files to " + out);
    Print("wrote " + JoinPath(out, "index.json") + " (" + std::to_string(pkgs.Size()) + " packages, sequence " +
          std::to_string(sequence) + ", expires " + FormatUtc(now + days * 86400) + ")");
    Print("fingerprint: " + pub.FingerprintDisplay());
    return 0;
}

int CmdVerify(std::vector<std::string> a) {
    std::string pubPath = Opt(a, "--public");
    if (pubPath.empty() || a.size() != 1) return Usage();
    std::string keyText, index, sig, err;
    PublicKey pub;
    if (!ReadFileBytes(pubPath, keyText) || !ParsePublicKey(keyText, pub, err)) return Fail("bad public key: " + err);
    if (!ReadFileBytes(JoinPath(a[0], "index.json"), index) || !ReadFileBytes(JoinPath(a[0], "index.json.sig"), sig))
        return Fail("cannot read index.json / index.json.sig in " + a[0]);
    IndexPolicy pol;
    pol.now = NowUnix();
    IndexCheck chk = VerifyIndex(index, sig, pub, pol);
    if (!chk.ok) return Fail(chk.error);
    Print("OK: repository '" + chk.index.repository + "', sequence " + std::to_string(chk.index.sequence) + ", " +
          std::to_string(chk.index.packages.size()) + " packages, expires " + FormatUtc(chk.index.expires));
    for (const auto& w : chk.index.warnings) Print("warning: " + w);
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> a;
    for (int i = 1; i < argc; ++i) a.push_back(Narrow(argv[i]));
    if (a.empty()) return Usage();
    std::string cmd = a[0];
    a.erase(a.begin());
    if (cmd == "keygen") return CmdKeygen(a);
    if (cmd == "lint") return CmdLint(a);
    if (cmd == "build") return CmdBuild(a);
    if (cmd == "verify") return CmdVerify(a);
    if (cmd == "fingerprint" && a.size() == 1) {
        std::string t, err;
        PublicKey p;
        if (!ReadFileBytes(a[0], t) || !ParsePublicKey(t, p, err)) return Fail("bad public key " + err);
        Print(p.FingerprintDisplay());
        Print(p.Fingerprint());
        return 0;
    }
    if (cmd == "hash" && a.size() == 1) {
        std::string hex, err;
        if (!Sha256File(a[0], hex, err)) return Fail(err);
        Print(hex + "  " + a[0] + "  (" + std::to_string(FileSize(a[0])) + " bytes)");
        return 0;
    }
    return Usage();
}
