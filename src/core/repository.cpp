#include "core/repository.h"

#include <algorithm>
#include <set>

#include "platform/http.h"
#include "platform/winutil.h"
#include "util/error.h"
#include "util/json.h"
#include "util/strings.h"

namespace sg {

namespace {
const uint64_t kMaxIndexBytes = 32ull << 20;
const uint64_t kMaxSmallFile = 64 * 1024;
}  // namespace

bool ParseSignatureFile(const std::string& text, SignatureFile& out, std::string& err) {
    auto pr = ParseJson(text);
    if (!pr.ok || !pr.value.IsObject()) {
        err = "signature file is not valid JSON";
        return false;
    }
    const Json& j = pr.value;
    auto str = [&](const char* k) {
        const Json* v = j.Find(k);
        return v && v->IsString() ? v->AsString() : std::string();
    };
    if (str("format") != "sevenget-sig-v1" || str("algorithm") != "ecdsa-p256-sha256") {
        err = "unsupported signature format or algorithm";
        return false;
    }
    out.keyFingerprint = ToLowerAscii(str("keyFingerprint"));
    if (!HexDecode(str("signature"), out.signature) || out.signature.size() != 64 || out.keyFingerprint.size() != 64) {
        err = "malformed signature file";
        return false;
    }
    return true;
}

std::string FormatSignatureFile(const PublicKey& key, const Bytes& signature) {
    Json j = Json::Object();
    j.Set("format", "sevenget-sig-v1");
    j.Set("algorithm", "ecdsa-p256-sha256");
    j.Set("keyFingerprint", key.Fingerprint());
    j.Set("signature", HexEncode(signature));
    return j.Dump(true) + "\n";
}

IndexCheck VerifyIndex(const std::string& indexBytes, const std::string& sigText, const PublicKey& key,
                       const IndexPolicy& policy) {
    IndexCheck r;
    r.code = kExitTrust;
    SignatureFile sig;
    std::string err;
    if (!ParseSignatureFile(sigText, sig, err)) {
        r.error = "repository signature invalid: " + err;
        return r;
    }
    const std::string enrolledFp = ToLowerAscii(key.Fingerprint());
    if (sig.keyFingerprint != enrolledFp) {
        r.error = "repository metadata is signed with an unexpected key (" + sig.keyFingerprint.substr(0, 16) +
                  "...) instead of the enrolled key (" + enrolledFp.substr(0, 16) + "...)";
        r.hint = "This can indicate a compromised server or a key rotation. Verify the new key fingerprint with the "
                 "repository operator out of band, then re-enroll with 'sevenget repo add <url> --replace'.";
        return r;
    }
    if (!VerifyEcdsaP256(key, indexBytes, sig.signature, err)) {
        r.error = "repository metadata signature verification failed (" + err + "); the metadata was modified or corrupted";
        return r;
    }
    // Only signed bytes are parsed from here on.
    auto pr = ParseJson(indexBytes);
    if (!pr.ok || !pr.value.IsObject()) {
        r.error = "signed repository index is not valid JSON: " + pr.error;
        return r;
    }
    const Json& j = pr.value;
    const Json* schema = j.Find("schema");
    if (!schema || !schema->IsInteger() || schema->AsInt() != 1) {
        r.error = "unsupported repository index schema";
        r.hint = "a newer SevenGet version may be required";
        return r;
    }
    auto str = [&](const char* k) {
        const Json* v = j.Find(k);
        return v && v->IsString() ? v->AsString() : std::string();
    };
    ParsedIndex& idx = r.index;
    idx.repository = str("repository");
    if (!IsValidRepoName(idx.repository)) {
        r.error = "repository index has an invalid repository name";
        return r;
    }
    if (!policy.expectedName.empty() && !EqualsIgnoreCase(policy.expectedName, idx.repository)) {
        r.error = "repository index names itself '" + idx.repository + "' but was enrolled as '" + policy.expectedName + "'";
        return r;
    }
    const Json* seq = j.Find("sequence");
    if (!seq || !seq->IsInteger() || seq->AsInt() <= 0) {
        r.error = "repository index has no valid sequence number";
        return r;
    }
    idx.sequence = seq->AsInt();
    if (!ParseUtc(str("generated"), idx.generated) || !ParseUtc(str("expires"), idx.expires) ||
        idx.expires <= idx.generated) {
        r.error = "repository index has invalid generated/expires timestamps";
        return r;
    }
    idx.sha256 = Sha256Hex(indexBytes);
    if (idx.sequence < policy.minSequence) {
        r.error = "repository metadata rollback detected: sequence " + std::to_string(idx.sequence) +
                  " is older than the previously accepted sequence " + std::to_string(policy.minSequence);
        r.hint = "a mirror or attacker may be serving stale metadata; SevenGet keeps using the newer metadata";
        return r;
    }
    if (idx.sequence == policy.minSequence && !policy.acceptedSha256.empty() &&
        !DigestEquals(idx.sha256, policy.acceptedSha256)) {
        r.error = "repository published different metadata under the same sequence number " +
                  std::to_string(idx.sequence);
        r.hint = "repository operators must increase 'sequence' for every change";
        return r;
    }
    if (policy.now > idx.expires) {
        if (!policy.allowExpired) {
            r.error = "repository metadata expired on " + FormatUtc(idx.expires);
            r.hint = "run 'sevenget update'; if it stays expired the repository is no longer maintained "
                     "(or the system clock is wrong)";
            return r;
        }
        r.expired = true;
    }
    if (idx.generated > policy.now + 86400)
        idx.warnings.push_back("repository metadata is dated in the future (" + FormatUtc(idx.generated) +
                               "); check the system clock");

    const Json* pkgs = j.Find("packages");
    if (!pkgs || !pkgs->IsArray()) {
        r.error = "repository index has no 'packages' array";
        return r;
    }
    std::set<std::string> ids;
    for (const auto& pj : pkgs->Items()) {
        Package p;
        std::vector<std::string> errors;
        if (!ParsePackage(pj, p, errors)) {
            idx.warnings.push_back("skipping invalid manifest: " + (errors.empty() ? "" : errors.front()));
            continue;
        }
        if (!ids.insert(ToLowerAscii(p.id)).second) {
            idx.warnings.push_back("skipping duplicate package id " + p.id);
            continue;
        }
        p.repository = idx.repository;
        idx.packages.push_back(std::move(p));
    }
    r.ok = true;
    r.code = 0;
    return r;
}

bool IsLocalRepoPath(const std::string& url) {
    if (url.size() >= 3 && ((url[0] >= 'A' && url[0] <= 'Z') || (url[0] >= 'a' && url[0] <= 'z')) && url[1] == ':' &&
        (url[2] == '\\' || url[2] == '/'))
        return true;
    return StartsWith(url, "\\\\") && !StartsWith(url, "\\\\?\\") && !StartsWith(url, "\\\\.\\");
}

bool RepositoryManager::FetchFile(const std::string& url, const std::string& name, uint64_t maxBytes,
                                  std::string& out, int& code, std::string& err) {
    if (IsLocalRepoPath(url)) {
        std::string p = JoinPath(url, name);
        if (!ReadFileBytes(p, out, maxBytes)) {
            code = FileExists(p) ? kExitError : kExitNotFound;
            err = "cannot read " + p;
            return false;
        }
        return true;
    }
    if (!IsHttpsUrl(url)) {
        code = kExitUsage;
        err = "repository URL must be https:// or an absolute local path: " + url;
        return false;
    }
    std::string full = url;
    if (!EndsWith(full, "/")) full += "/";
    full += name;
    HttpError herr;
    if (!HttpGetString(full, maxBytes, out, herr)) {
        code = herr.kind == HttpError::Kind::Cancelled ? kExitCancelled
               : herr.kind == HttpError::Kind::Http && herr.httpStatus == 404 ? kExitNotFound
                                                                               : kExitNetwork;
        err = herr.message + (herr.hint.empty() ? "" : "\n  " + herr.hint);
        return false;
    }
    return true;
}

bool RepositoryManager::FetchPublicKey(const std::string& url, std::string& keyText, int& code, std::string& err) {
    return FetchFile(url, "key.pub", kMaxSmallFile, keyText, code, err);
}

IndexCheck RepositoryManager::Probe(const std::string& url, const PublicKey& key) {
    IndexCheck r;
    int code = 0;
    std::string err;
    probedIndex_.clear();
    probedSig_.clear();
    if (!FetchFile(url, "index.json", kMaxIndexBytes, probedIndex_, code, err) ||
        !FetchFile(url, "index.json.sig", kMaxSmallFile, probedSig_, code, err)) {
        r.code = code;
        r.error = err;
        return r;
    }
    IndexPolicy pol;
    pol.now = NowUnix();
    return VerifyIndex(probedIndex_, probedSig_, key, pol);
}

std::string RepositoryManager::CacheDir(const std::string& repoName) const {
    return JoinPath(JoinPath(GetAppPaths().cacheDir, "repos"), ToLowerAscii(repoName));
}

void RepositoryManager::StoreCache(const std::string& repoName, int64_t sequence, const std::string& index,
                                   const std::string& sig) {
    std::string dir = CacheDir(repoName);
    if (!CreateDirectories(dir)) throw Error(kExitError, "cannot create cache directory " + dir);
    std::string base = JoinPath(dir, "index-" + std::to_string(sequence));
    if (!WriteFileAtomic(base + ".json", index) || !WriteFileAtomic(base + ".json.sig", sig))
        throw Error(kExitError, "cannot write repository cache in " + dir);
}

void RepositoryManager::Enroll(const std::string& name, const std::string& url, const PublicKey& key,
                               const IndexCheck& probe, const std::string& indexBytes, const std::string& sigText) {
    StoreCache(name, probe.index.sequence, indexBytes, sigText);
    RepoRecord rec;
    RepoRecord old;
    bool existed = db_.GetRepo(name, old);
    rec.name = name;
    rec.url = url;
    rec.publicKey = FormatPublicKey(key);
    rec.fingerprint = key.Fingerprint();
    rec.priority = existed ? old.priority : static_cast<int64_t>(db_.ListRepos().size());
    rec.enabled = true;
    // Re-enrolling never lowers the rollback watermark for the same name.
    rec.sequence = probe.index.sequence;
    rec.expires = probe.index.expires;
    rec.indexSha256 = probe.index.sha256;
    rec.updatedAt = NowUnix();
    rec.addedAt = existed ? old.addedAt : NowUnix();
    if (existed && old.sequence > rec.sequence)
        throw Error(kExitTrust, "refusing to re-enroll '" + name + "': offered metadata sequence " +
                                    std::to_string(rec.sequence) + " is older than the accepted " +
                                    std::to_string(old.sequence));
    db_.PutRepo(rec);
}

IndexCheck RepositoryManager::Update(const RepoRecord& repo) {
    IndexCheck r;
    PublicKey key;
    std::string err;
    if (!ParsePublicKey(repo.publicKey, key, err)) {
        r.code = kExitTrust;
        r.error = "stored key for repository '" + repo.name + "' is invalid: " + err;
        return r;
    }
    std::string index, sig;
    int code = 0;
    if (!FetchFile(repo.url, "index.json", kMaxIndexBytes, index, code, err) ||
        !FetchFile(repo.url, "index.json.sig", kMaxSmallFile, sig, code, err)) {
        r.code = code;
        r.error = err;
        return r;
    }
    IndexPolicy pol;
    pol.now = NowUnix();
    pol.minSequence = repo.sequence;
    pol.acceptedSha256 = repo.indexSha256;
    pol.expectedName = repo.name;
    r = VerifyIndex(index, sig, key, pol);
    if (!r.ok) return r;
    if (r.index.sequence == repo.sequence) return r;  // unchanged
    StoreCache(repo.name, r.index.sequence, index, sig);
    RepoRecord updated = repo;
    updated.sequence = r.index.sequence;
    updated.expires = r.index.expires;
    updated.indexSha256 = r.index.sha256;
    updated.updatedAt = NowUnix();
    db_.PutRepo(updated);  // the commit is the atomic switch to the new metadata
    // Remove superseded cache files.
    std::string dir = CacheDir(repo.name);
    for (const auto& f : ListDirectory(dir)) {
        if (StartsWith(f, "index-") && f.find("index-" + std::to_string(r.index.sequence) + ".") == std::string::npos)
            DeleteFileUtf8(JoinPath(dir, f));
    }
    return r;
}

void RepositoryManager::LoadAll(bool allowExpired, std::vector<std::string>& warnings) {
    packages_.clear();
    std::set<std::string> seen;
    for (const auto& repo : db_.ListRepos()) {
        if (!repo.enabled) continue;
        PublicKey key;
        std::string err;
        if (!ParsePublicKey(repo.publicKey, key, err)) {
            warnings.push_back("repository '" + repo.name + "': invalid stored key");
            continue;
        }
        std::string base = JoinPath(CacheDir(repo.name), "index-" + std::to_string(repo.sequence));
        std::string index, sig;
        if (!ReadFileBytes(base + ".json", index, kMaxIndexBytes) || !ReadFileBytes(base + ".json.sig", sig, kMaxSmallFile)) {
            warnings.push_back("repository '" + repo.name + "' has no cached metadata; run 'sevenget update'");
            continue;
        }
        IndexPolicy pol;
        pol.now = NowUnix();
        pol.minSequence = repo.sequence;
        pol.acceptedSha256 = repo.indexSha256;
        pol.expectedName = repo.name;
        pol.allowExpired = allowExpired;
        IndexCheck r = VerifyIndex(index, sig, key, pol);
        if (!r.ok) {
            warnings.push_back("repository '" + repo.name + "': " + r.error);
            continue;
        }
        if (r.expired)
            warnings.push_back("repository '" + repo.name + "' metadata expired on " + FormatUtc(r.index.expires) +
                               "; run 'sevenget update' (installation from it is blocked)");
        for (auto& w : r.index.warnings) warnings.push_back("repository '" + repo.name + "': " + w);
        for (auto& p : r.index.packages) {
            // Earlier (higher-priority) repositories win on id collisions.
            if (!seen.insert(ToLowerAscii(p.id)).second) continue;
            packages_.push_back(std::move(p));
        }
    }
}

const Package* RepositoryManager::Find(const std::string& id) const {
    for (const auto& p : packages_)
        if (EqualsIgnoreCase(p.id, id)) return &p;
    return nullptr;
}

std::vector<const Package*> RepositoryManager::Search(const std::string& query) const {
    std::vector<std::pair<int, const Package*>> scored;
    for (const auto& p : packages_) {
        int score = 0;
        if (EqualsIgnoreCase(p.id, query) || EqualsIgnoreCase(p.name, query)) score = 100;
        else if (ContainsIgnoreCase(p.id, query) || ContainsIgnoreCase(p.name, query)) score = 50;
        else {
            for (const auto& t : p.tags)
                if (EqualsIgnoreCase(t, query)) score = 30;
            if (!score && (ContainsIgnoreCase(p.description, query) || ContainsIgnoreCase(p.publisher, query))) score = 10;
        }
        if (query.empty()) score = 1;
        if (score) scored.push_back({score, &p});
    }
    std::stable_sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first > b.first;
        return ToLowerAscii(a.second->id) < ToLowerAscii(b.second->id);
    });
    std::vector<const Package*> out;
    for (auto& s : scored) out.push_back(s.second);
    return out;
}

}  // namespace sg
