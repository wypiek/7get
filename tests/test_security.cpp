// Cryptography and repository trust tests: hashes, ECDSA, signed index
// verification (tampering, key change, rollback, equivocation, expiry).
#include "core/repository.h"
#include "fixtures.h"
#include "platform/crypto.h"
#include "platform/winutil.h"
#include "test.h"
#include "util/error.h"
#include "util/strings.h"

using namespace sg;

namespace {

// Same OpenSSL-generated vector used by 'sevenget doctor'.
const char kPub[] =
    "sevenget-pubkey-v1 ecdsa-p256 "
    "047fc62733e0e26f8a9ed6e1553e09f8c01f38c9eb76f1e57bb4d666b7cc9ef408337eacdc9f9fb3df8e576a40e37f3bd8f5ade3c00bdffe2cddd1280f35cec110";
const char kSig[] =
    "ad78637634eb49d7db0aa05adcf4ee8189780978a5d6a052c0e8674aad7060fda9985bc930b4e8574627a8f1fe4fd0468bf583a87c66c94c5a5a0a1cd4b40262";
const char kMsg[] = "SevenGet CNG ECDSA P-256 self-test vector";

struct Signer {
    PrivateKey priv;
    PublicKey pub;
    bool ok = false;
    Signer() {
        std::string err;
        ok = GenerateKeyPair(priv, pub, err);
        if (!ok) ::sgtest::ReportFailure(__FILE__, __LINE__, "key generation failed: " + err);
    }
    std::string Sign(const std::string& text) {
        Bytes sig;
        std::string err;
        if (!SignEcdsaP256(priv, text, sig, err)) ::sgtest::ReportFailure(__FILE__, __LINE__, "sign failed: " + err);
        return FormatSignatureFile(pub, sig);
    }
};

std::string IndexText(int64_t sequence, const std::string& expires, const std::string& extraPackage = "",
                      const std::string& name = "testrepo") {
    std::string pkgs = sgtest::SampleManifestText();
    if (!extraPackage.empty()) pkgs += "," + extraPackage;
    return "{\"schema\": 1, \"repository\": \"" + name + "\", \"sequence\": " + std::to_string(sequence) +
           ", \"generated\": \"2026-01-01T00:00:00Z\", \"expires\": \"" + expires + "\", \"packages\": [" + pkgs + "]}";
}

IndexPolicy Policy(int64_t minSeq = 0, const std::string& sha = "") {
    IndexPolicy p;
    ParseUtc("2026-06-01T00:00:00Z", p.now);
    p.minSequence = minSeq;
    p.acceptedSha256 = sha;
    return p;
}

}  // namespace

TEST(sha256_known_answers) {
    CHECK_EQ(Sha256Hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(Sha256Hex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    std::string million(1000000, 'a');
    CHECK_EQ(Sha256Hex(million), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    CHECK(DigestEquals("ABCDEF", "abcdef"));
    CHECK(!DigestEquals("abcdef", "abcdee"));
    CHECK(!DigestEquals("abc", "abcd"));
}

TEST(sha256_file_detects_tampering) {
    std::string dir = sgtest::TempDir("hash");
    std::string f = JoinPath(dir, "pkg \xC3\xA9.bin");
    CHECK(WriteFileAtomic(f, "abc"));
    std::string hex, err;
    CHECK(Sha256File(f, hex, err));
    CHECK(DigestEquals(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(WriteFileAtomic(f, "abd"));  // one byte changed
    CHECK(Sha256File(f, hex, err));
    CHECK(!DigestEquals(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(!Sha256File(JoinPath(dir, "missing.bin"), hex, err));
}

TEST(ecdsa_verifies_openssl_signature) {
    PublicKey k;
    std::string err;
    Bytes sig;
    CHECK(ParsePublicKey(kPub, k, err));
    CHECK(HexDecode(kSig, sig));
    CHECK(VerifyEcdsaP256(k, kMsg, sig, err));
    CHECK(!VerifyEcdsaP256(k, std::string(kMsg) + "!", sig, err));
    sig[10] ^= 1;
    CHECK(!VerifyEcdsaP256(k, kMsg, sig, err));
    CHECK(!ParsePublicKey("sevenget-pubkey-v1 ecdsa-p256 0400", k, err));
    CHECK(!ParsePublicKey("ssh-ed25519 AAAA", k, err));
    CHECK_EQ(k.FingerprintDisplay().size(), static_cast<size_t>(79));  // 16 groups of 4 + 15 spaces
}

TEST(ecdsa_sign_verify_roundtrip_and_key_format) {
    Signer s;
    if (!s.ok) return;
    Bytes sig;
    std::string err;
    CHECK(SignEcdsaP256(s.priv, "hello", sig, err));
    CHECK(VerifyEcdsaP256(s.pub, "hello", sig, err));
    PrivateKey back;
    CHECK(ParsePrivateKey(FormatPrivateKey(s.priv), back, err));
    CHECK(back.d == s.priv.d);
    PublicKey pub2;
    CHECK(ParsePublicKey(FormatPublicKey(s.pub), pub2, err));
    CHECK(pub2.Fingerprint() == s.pub.Fingerprint());
}

TEST(index_good_signature_accepted) {
    Signer s;
    if (!s.ok) return;
    std::string idx = IndexText(5, "2027-01-01T00:00:00Z");
    IndexCheck r = VerifyIndex(idx, s.Sign(idx), s.pub, Policy());
    CHECK(r.ok);
    CHECK(r.index.sequence == 5);
    CHECK(r.index.packages.size() == 1);
    CHECK_EQ(r.index.packages[0].repository, std::string("testrepo"));
}

TEST(index_tampering_rejected) {
    Signer s;
    if (!s.ok) return;
    std::string idx = IndexText(5, "2027-01-01T00:00:00Z");
    std::string sig = s.Sign(idx);
    std::string tampered = idx;
    tampered.replace(tampered.find("2222"), 4, "2223");  // alter a SHA-256 in a manifest
    IndexCheck r = VerifyIndex(tampered, sig, s.pub, Policy());
    CHECK(!r.ok && r.code == kExitTrust);
    CHECK(r.error.find("signature verification failed") != std::string::npos);
    // Whitespace-only change is also rejected (signature covers exact bytes).
    r = VerifyIndex(idx + " ", sig, s.pub, Policy());
    CHECK(!r.ok);
    // Garbage signature file.
    r = VerifyIndex(idx, "{\"format\": \"other\"}", s.pub, Policy());
    CHECK(!r.ok);
}

TEST(index_unexpected_key_change_rejected) {
    Signer enrolled, attacker;
    if (!enrolled.ok || !attacker.ok) return;
    std::string idx = IndexText(6, "2027-01-01T00:00:00Z");
    IndexCheck r = VerifyIndex(idx, attacker.Sign(idx), enrolled.pub, Policy());
    CHECK(!r.ok && r.code == kExitTrust);
    CHECK(r.error.find("unexpected key") != std::string::npos);
    CHECK(!r.hint.empty());
    // Signature claims the enrolled fingerprint but was made with another key.
    std::string forged = attacker.Sign(idx);
    std::string fpA = attacker.pub.Fingerprint(), fpE = enrolled.pub.Fingerprint();
    forged.replace(forged.find(fpA), fpA.size(), fpE);
    r = VerifyIndex(idx, forged, enrolled.pub, Policy());
    CHECK(!r.ok && r.code == kExitTrust);
}

TEST(index_rollback_and_equivocation_rejected) {
    Signer s;
    if (!s.ok) return;
    std::string v5 = IndexText(5, "2027-01-01T00:00:00Z");
    std::string v4 = IndexText(4, "2027-01-01T00:00:00Z");
    IndexCheck r = VerifyIndex(v4, s.Sign(v4), s.pub, Policy(5, Sha256Hex(v5)));
    CHECK(!r.ok && r.code == kExitTrust);
    CHECK(r.error.find("rollback") != std::string::npos);
    // Same sequence, same bytes: fine (no-op update).
    r = VerifyIndex(v5, s.Sign(v5), s.pub, Policy(5, Sha256Hex(v5)));
    CHECK(r.ok);
    // Same sequence, different content: rejected.
    std::string v5b = IndexText(5, "2027-02-01T00:00:00Z");
    r = VerifyIndex(v5b, s.Sign(v5b), s.pub, Policy(5, Sha256Hex(v5)));
    CHECK(!r.ok);
    // Newer sequence accepted.
    std::string v6 = IndexText(6, "2027-01-01T00:00:00Z");
    r = VerifyIndex(v6, s.Sign(v6), s.pub, Policy(5, Sha256Hex(v5)));
    CHECK(r.ok);
}

TEST(index_expiry_enforced) {
    Signer s;
    if (!s.ok) return;
    std::string idx = IndexText(7, "2026-03-01T00:00:00Z");  // before Policy().now
    IndexCheck r = VerifyIndex(idx, s.Sign(idx), s.pub, Policy());
    CHECK(!r.ok && r.code == kExitTrust);
    CHECK(r.error.find("expired") != std::string::npos);
    IndexPolicy p = Policy();
    p.allowExpired = true;  // read-only commands
    r = VerifyIndex(idx, s.Sign(idx), s.pub, p);
    CHECK(r.ok && r.expired);
    // expires before generated is malformed
    std::string bad = IndexText(7, "2025-01-01T00:00:00Z");
    r = VerifyIndex(bad, s.Sign(bad), s.pub, p);
    CHECK(!r.ok);
}

TEST(index_structure_and_name_checks) {
    Signer s;
    if (!s.ok) return;
    // Invalid manifest inside a validly signed index is skipped, not fatal.
    std::string broken = R"({"id": "../evil", "name": "x", "publisher": "x", "description": "x", "releases": []})";
    std::string idx = IndexText(8, "2027-01-01T00:00:00Z", broken);
    IndexCheck r = VerifyIndex(idx, s.Sign(idx), s.pub, Policy());
    CHECK(r.ok && r.index.packages.size() == 1 && !r.index.warnings.empty());
    // Duplicate ids: the second is skipped.
    idx = IndexText(8, "2027-01-01T00:00:00Z", sgtest::SampleManifestText("example.tool"));
    r = VerifyIndex(idx, s.Sign(idx), s.pub, Policy());
    CHECK(r.ok && r.index.packages.size() == 1);
    // Repository name must match the enrolled name.
    idx = IndexText(8, "2027-01-01T00:00:00Z", "", "otherrepo");
    IndexPolicy p = Policy();
    p.expectedName = "testrepo";
    r = VerifyIndex(idx, s.Sign(idx), s.pub, p);
    CHECK(!r.ok);
    // Unsupported schema.
    std::string v2 = IndexText(8, "2027-01-01T00:00:00Z");
    v2.replace(v2.find("\"schema\": 1"), 11, "\"schema\": 2");
    r = VerifyIndex(v2, s.Sign(v2), s.pub, Policy());
    CHECK(!r.ok);
}
