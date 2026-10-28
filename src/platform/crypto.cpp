#include "platform/crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>

#include "util/strings.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace sg {

namespace {

class AlgHandle {
public:
    AlgHandle(LPCWSTR alg, ULONG flags = 0) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&h_, alg, nullptr, flags))) h_ = nullptr;
    }
    ~AlgHandle() {
        if (h_) BCryptCloseAlgorithmProvider(h_, 0);
    }
    BCRYPT_ALG_HANDLE get() const { return h_; }
private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class Sha256Ctx {
public:
    Sha256Ctx() : alg_(BCRYPT_SHA256_ALGORITHM) {
        if (!alg_.get()) return;
        DWORD objLen = 0, got = 0;
        if (!NT_SUCCESS(BCryptGetProperty(alg_.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen),
                                          sizeof objLen, &got, 0)))
            return;
        obj_.resize(objLen);
        if (!NT_SUCCESS(BCryptCreateHash(alg_.get(), &hash_, obj_.data(), objLen, nullptr, 0, 0))) hash_ = nullptr;
    }
    ~Sha256Ctx() {
        if (hash_) BCryptDestroyHash(hash_);
    }
    bool ok() const { return hash_ != nullptr; }
    bool Update(const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        while (n > 0) {
            ULONG chunk = static_cast<ULONG>(n > 0x40000000 ? 0x40000000 : n);
            if (!NT_SUCCESS(BCryptHashData(hash_, const_cast<PUCHAR>(b), chunk, 0))) return false;
            b += chunk;
            n -= chunk;
        }
        return true;
    }
    bool Final(Bytes& out) {
        out.assign(32, 0);
        return NT_SUCCESS(BCryptFinishHash(hash_, out.data(), 32, 0));
    }
private:
    AlgHandle alg_;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<UCHAR> obj_;
};

}  // namespace

bool Sha256(const void* data, size_t len, Bytes& digest) {
    Sha256Ctx ctx;
    return ctx.ok() && ctx.Update(data, len) && ctx.Final(digest);
}

std::string Sha256Hex(const std::string& data) {
    Bytes d;
    if (!Sha256(data.data(), data.size(), d)) return {};
    return HexEncode(d);
}

bool Sha256File(const std::string& path, std::string& hex, std::string& err,
                const std::function<bool(uint64_t)>& progress) {
    HANDLE h = CreateFileW(Widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "cannot open file for hashing";
        return false;
    }
    Sha256Ctx ctx;
    if (!ctx.ok()) {
        CloseHandle(h);
        err = "SHA-256 provider unavailable (bcrypt.dll)";
        return false;
    }
    std::vector<uint8_t> buf(1 << 20);
    uint64_t done = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
            CloseHandle(h);
            err = "read error while hashing";
            return false;
        }
        if (got == 0) break;
        ctx.Update(buf.data(), got);
        done += got;
        if (progress && !progress(done)) {
            CloseHandle(h);
            err = "cancelled";
            return false;
        }
    }
    CloseHandle(h);
    Bytes d;
    if (!ctx.Final(d)) {
        err = "SHA-256 finalization failed";
        return false;
    }
    hex = HexEncode(d);
    return true;
}

bool DigestEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char x = static_cast<unsigned char>(a[i]), y = static_cast<unsigned char>(b[i]);
        if (x >= 'A' && x <= 'Z') x = static_cast<unsigned char>(x + 32);
        if (y >= 'A' && y <= 'Z') y = static_cast<unsigned char>(y + 32);
        diff |= static_cast<unsigned>(x ^ y);
    }
    return diff == 0;
}

std::string PublicKey::Fingerprint() const {
    Bytes d;
    if (!Sha256(point.data(), point.size(), d)) return {};
    return HexEncode(d);
}

std::string PublicKey::FingerprintDisplay() const {
    std::string fp = ToLowerAscii(Fingerprint());
    for (auto& c : fp)
        if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 32);
    std::string out;
    for (size_t i = 0; i < fp.size(); i += 4) {
        if (i) out += ' ';
        out += fp.substr(i, 4);
    }
    return out;
}

bool ParsePublicKey(const std::string& text, PublicKey& out, std::string& err) {
    auto parts = Split(Trim(text), ' ');
    if (parts.size() != 3 || parts[0] != "sevenget-pubkey-v1" || parts[1] != "ecdsa-p256") {
        err = "not a SevenGet public key (expected 'sevenget-pubkey-v1 ecdsa-p256 <hex>')";
        return false;
    }
    Bytes p;
    if (!HexDecode(parts[2], p) || p.size() != 65 || p[0] != 0x04) {
        err = "malformed ECDSA P-256 public key point";
        return false;
    }
    out.point = p;
    return true;
}

std::string FormatPublicKey(const PublicKey& k) { return "sevenget-pubkey-v1 ecdsa-p256 " + HexEncode(k.point); }

bool VerifyEcdsaP256(const PublicKey& key, const std::string& message, const Bytes& signature, std::string& err) {
    if (key.point.size() != 65 || signature.size() != 64) {
        err = "invalid key or signature length";
        return false;
    }
    AlgHandle alg(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!alg.get()) {
        err = "ECDSA P-256 provider unavailable (bcrypt.dll)";
        return false;
    }
    std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey = 32;
    std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), key.point.data() + 1, 64);
    BCRYPT_KEY_HANDLE hk = nullptr;
    if (!NT_SUCCESS(BCryptImportKeyPair(alg.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, &hk, blob.data(),
                                        static_cast<ULONG>(blob.size()), 0))) {
        err = "cannot import repository public key";
        return false;
    }
    Bytes digest;
    if (!Sha256(message.data(), message.size(), digest)) {
        BCryptDestroyKey(hk);
        err = "SHA-256 failed";
        return false;
    }
    NTSTATUS st = BCryptVerifySignature(hk, nullptr, digest.data(), 32, const_cast<PUCHAR>(signature.data()), 64, 0);
    BCryptDestroyKey(hk);
    if (!NT_SUCCESS(st)) {
        err = "signature does not match";
        return false;
    }
    return true;
}

bool RandomBytes(void* buf, size_t len) {
    return NT_SUCCESS(BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), static_cast<ULONG>(len),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool GenerateKeyPair(PrivateKey& priv, PublicKey& pub, std::string& err) {
    AlgHandle alg(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!alg.get()) { err = "ECDSA P-256 provider unavailable"; return false; }
    BCRYPT_KEY_HANDLE hk = nullptr;
    if (!NT_SUCCESS(BCryptGenerateKeyPair(alg.get(), &hk, 256, 0)) || !NT_SUCCESS(BCryptFinalizeKeyPair(hk, 0))) {
        err = "key generation failed";
        return false;
    }
    ULONG size = 0;
    BCryptExportKey(hk, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &size, 0);
    std::vector<uint8_t> blob(size);
    NTSTATUS st = BCryptExportKey(hk, nullptr, BCRYPT_ECCPRIVATE_BLOB, blob.data(), size, &size, 0);
    BCryptDestroyKey(hk);
    if (!NT_SUCCESS(st) || size != sizeof(BCRYPT_ECCKEY_BLOB) + 96) { err = "key export failed"; return false; }
    const uint8_t* p = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    priv.x.assign(p, p + 32);
    priv.y.assign(p + 32, p + 64);
    priv.d.assign(p + 64, p + 96);
    SecureZeroMemory(blob.data(), blob.size());
    pub = PublicFromPrivate(priv);
    return true;
}

PublicKey PublicFromPrivate(const PrivateKey& k) {
    PublicKey pub;
    pub.point.push_back(0x04);
    pub.point.insert(pub.point.end(), k.x.begin(), k.x.end());
    pub.point.insert(pub.point.end(), k.y.begin(), k.y.end());
    return pub;
}

bool SignEcdsaP256(const PrivateKey& key, const std::string& message, Bytes& signature, std::string& err) {
    AlgHandle alg(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!alg.get()) { err = "ECDSA P-256 provider unavailable"; return false; }
    std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 96);
    auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    hdr->cbKey = 32;
    uint8_t* p = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    std::memcpy(p, key.x.data(), 32);
    std::memcpy(p + 32, key.y.data(), 32);
    std::memcpy(p + 64, key.d.data(), 32);
    BCRYPT_KEY_HANDLE hk = nullptr;
    NTSTATUS st = BCryptImportKeyPair(alg.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, &hk, blob.data(),
                                      static_cast<ULONG>(blob.size()), 0);
    SecureZeroMemory(blob.data(), blob.size());
    if (!NT_SUCCESS(st)) { err = "cannot import private key"; return false; }
    Bytes digest;
    Sha256(message.data(), message.size(), digest);
    ULONG len = 0;
    signature.assign(64, 0);
    st = BCryptSignHash(hk, nullptr, digest.data(), 32, signature.data(), 64, &len, 0);
    BCryptDestroyKey(hk);
    if (!NT_SUCCESS(st) || len != 64) { err = "signing failed"; return false; }
    return true;
}

bool ParsePrivateKey(const std::string& text, PrivateKey& out, std::string& err) {
    auto parts = Split(Trim(text), ' ');
    Bytes b;
    if (parts.size() != 3 || parts[0] != "sevenget-privkey-v1" || parts[1] != "ecdsa-p256" ||
        !HexDecode(parts[2], b) || b.size() != 96) {
        err = "not a SevenGet private key";
        return false;
    }
    out.x.assign(b.begin(), b.begin() + 32);
    out.y.assign(b.begin() + 32, b.begin() + 64);
    out.d.assign(b.begin() + 64, b.end());
    return true;
}

std::string FormatPrivateKey(const PrivateKey& k) {
    Bytes b = k.x;
    b.insert(b.end(), k.y.begin(), k.y.end());
    b.insert(b.end(), k.d.begin(), k.d.end());
    return "sevenget-privkey-v1 ecdsa-p256 " + HexEncode(b);
}

}  // namespace sg
