// SevenGet - Authenticode verification through WinVerifyTrust (wintrust.dll).
#pragma once

#include <string>

namespace sg {

enum class RevocationMode { Soft, Hard };

struct AuthenticodeResult {
    enum class Status {
        Valid,          // trusted chain, signature intact
        NotSigned,      // no embedded signature
        Invalid,        // tampered, untrusted root, expired without timestamp, etc.
        Error,          // verification could not be performed
    } status = Status::Error;
    long trustError = 0;          // HRESULT from WinVerifyTrust
    std::string signerSubject;    // simple display name of the leaf signer
    std::string message;          // human-readable explanation
    bool revocationUnchecked = false;  // soft mode: revocation server unreachable
};

// Verifies the embedded Authenticode signature of a PE or MSI file.
// No UI is ever shown. In Soft revocation mode an offline revocation server is
// tolerated (reported via revocationUnchecked); in Hard mode it fails.
AuthenticodeResult VerifyAuthenticode(const std::string& path, RevocationMode mode);

}  // namespace sg
