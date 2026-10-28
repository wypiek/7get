// SevenGet - cryptography through Windows CNG (bcrypt.dll, Windows Vista+).
//
//  * SHA-256 digests of files and buffers.
//  * ECDSA P-256 / SHA-256 repository metadata signatures. Signatures are the
//    64-byte IEEE P1363 encoding r||s; public keys are the 65-byte uncompressed
//    SEC1 point 04||X||Y. Key fingerprints are SHA-256 over that point.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sg {

using Bytes = std::vector<uint8_t>;

// Returns false only on CNG failure.
bool Sha256(const void* data, size_t len, Bytes& digest);
std::string Sha256Hex(const std::string& data);

// Streams a file through SHA-256. progress(bytesDone) may return false to cancel.
// Returns false if the file cannot be read or cancelled; err explains why.
bool Sha256File(const std::string& path, std::string& hexDigest, std::string& err,
                const std::function<bool(uint64_t)>& progress = {});

// Constant-time comparison of equal-length hex digests (case-insensitive).
bool DigestEquals(const std::string& a, const std::string& b);

struct PublicKey {
    Bytes point;  // 65 bytes: 0x04 || X(32) || Y(32)
    std::string Fingerprint() const;         // lowercase hex SHA-256 of point
    std::string FingerprintDisplay() const;  // "ABCD 1234 ..." groups of 4
};

// Public key text format (key.pub):  "sevenget-pubkey-v1 ecdsa-p256 <130 hex chars>"
bool ParsePublicKey(const std::string& text, PublicKey& out, std::string& err);
std::string FormatPublicKey(const PublicKey& k);

bool VerifyEcdsaP256(const PublicKey& key, const std::string& message, const Bytes& signature, std::string& err);

// Signing support (used by sevenget-repotool; never by the client).
struct PrivateKey {
    Bytes x, y, d;  // 32 bytes each
};
bool GenerateKeyPair(PrivateKey& priv, PublicKey& pub, std::string& err);
bool SignEcdsaP256(const PrivateKey& key, const std::string& message, Bytes& signature, std::string& err);
// Private key text format: "sevenget-privkey-v1 ecdsa-p256 <hex X||Y||d>"
bool ParsePrivateKey(const std::string& text, PrivateKey& out, std::string& err);
std::string FormatPrivateKey(const PrivateKey& k);
PublicKey PublicFromPrivate(const PrivateKey& k);

bool RandomBytes(void* buf, size_t len);

}  // namespace sg
