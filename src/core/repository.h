// SevenGet - signed repository metadata.
//
// A repository is a directory (served over HTTPS or on a local/UNC path)
// containing:
//    key.pub          - repository public key (only used during enrollment)
//    index.json       - all package manifests plus sequence/expiry metadata
//    index.json.sig   - ECDSA P-256 signature over the exact bytes of index.json
//
// Trust model (docs/security.md):
//  * A repository key is trusted only after explicit enrollment, where the
//    user confirms the key fingerprint (or passes --fingerprint).
//  * Every load verifies the signature with the enrolled key; a signature by
//    any other key is reported as an unexpected key change and rejected.
//  * The accepted "sequence" never decreases (rollback protection) and an
//    identical sequence must carry identical content (equivocation).
//  * Metadata past its "expires" timestamp is refused for installation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/database.h"
#include "core/manifest.h"
#include "platform/crypto.h"

namespace sg {

struct SignatureFile {
    std::string keyFingerprint;
    Bytes signature;
};
bool ParseSignatureFile(const std::string& text, SignatureFile& out, std::string& err);
std::string FormatSignatureFile(const PublicKey& key, const Bytes& signature);

struct ParsedIndex {
    std::string repository;
    int64_t sequence = 0;
    int64_t generated = 0;
    int64_t expires = 0;
    std::string sha256;
    std::vector<Package> packages;
    std::vector<std::string> warnings;  // invalid manifests that were skipped, clock skew...
};

struct IndexCheck {
    bool ok = false;
    int code = 0;           // ExitCode
    std::string error;
    std::string hint;
    bool expired = false;   // set (with ok=true) when allowExpired was used
    ParsedIndex index;
};

struct IndexPolicy {
    int64_t now = 0;
    int64_t minSequence = 0;         // highest previously accepted sequence
    std::string acceptedSha256;      // digest accepted at minSequence ("" = none)
    std::string expectedName;        // "" = accept any valid name (first enrollment)
    bool allowExpired = false;       // read-only commands may show expired data with a warning
};

// Pure verification function (unit tested): signature, key identity,
// structure, rollback, expiry, manifest validation.
IndexCheck VerifyIndex(const std::string& indexBytes, const std::string& sigText, const PublicKey& key,
                       const IndexPolicy& policy);

bool IsLocalRepoPath(const std::string& url);

class RepositoryManager {
public:
    explicit RepositoryManager(Database& db) : db_(db) {}

    // Downloads "<url>/key.pub". Local paths are read from disk.
    bool FetchPublicKey(const std::string& url, std::string& keyText, int& code, std::string& err);

    // Fetches and verifies the index with the given key; used by `repo add`
    // before the repository is stored.
    IndexCheck Probe(const std::string& url, const PublicKey& key);

    // Stores a verified repository (after the user confirmed the key).
    void Enroll(const std::string& name, const std::string& url, const PublicKey& key, const IndexCheck& probe,
                const std::string& indexBytes, const std::string& sigText);

    // `sevenget update` for one repository. Returns check result; on success
    // the cache and the database are updated atomically.
    IndexCheck Update(const RepoRecord& repo);

    // Loads verified cached metadata of all enabled repositories.
    // Repositories without valid cache are reported in warnings.
    void LoadAll(bool allowExpired, std::vector<std::string>& warnings);

    const std::vector<Package>& Packages() const { return packages_; }
    const Package* Find(const std::string& id) const;
    std::vector<const Package*> Search(const std::string& query) const;

    std::string CacheDir(const std::string& repoName) const;

    // Last raw bytes fetched by Probe() (used by Enroll()).
    const std::string& probedIndex() const { return probedIndex_; }
    const std::string& probedSig() const { return probedSig_; }

private:
    bool FetchFile(const std::string& url, const std::string& name, uint64_t maxBytes, std::string& out, int& code,
                   std::string& err);
    void StoreCache(const std::string& repoName, int64_t sequence, const std::string& index, const std::string& sig);

    Database& db_;
    std::vector<Package> packages_;
    std::string probedIndex_, probedSig_;
};

}  // namespace sg
