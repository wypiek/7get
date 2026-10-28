#include "platform/authenticode.h"

#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <cstdio>

#include "util/strings.h"

namespace sg {

namespace {

std::string HrText(long hr) {
    switch (static_cast<unsigned long>(hr)) {
        case static_cast<unsigned long>(TRUST_E_NOSIGNATURE): return "file is not signed";
        case static_cast<unsigned long>(TRUST_E_BAD_DIGEST): return "signature digest mismatch (file modified after signing)";
        case static_cast<unsigned long>(TRUST_E_EXPLICIT_DISTRUST): return "signer certificate is explicitly distrusted";
        case static_cast<unsigned long>(TRUST_E_SUBJECT_NOT_TRUSTED): return "subject not trusted";
        case static_cast<unsigned long>(CERT_E_UNTRUSTEDROOT): return "certificate chain ends in an untrusted root (Windows 7 may need root certificate updates)";
        case static_cast<unsigned long>(CERT_E_CHAINING): return "certificate chain could not be built";
        case static_cast<unsigned long>(CERT_E_EXPIRED): return "certificate expired and signature is not timestamped";
        case static_cast<unsigned long>(CERT_E_REVOKED): return "signer certificate has been revoked";
        case static_cast<unsigned long>(CRYPT_E_REVOKED): return "signer certificate has been revoked";
        case static_cast<unsigned long>(CERT_E_REVOCATION_FAILURE): return "revocation status could not be checked";
        case static_cast<unsigned long>(CRYPT_E_REVOCATION_OFFLINE): return "revocation server offline";
        case static_cast<unsigned long>(TRUST_E_PROVIDER_UNKNOWN): return "trust provider unknown";
        case static_cast<unsigned long>(TRUST_E_SUBJECT_FORM_UNKNOWN): return "file format not supported for signature verification";
        case static_cast<unsigned long>(CRYPT_E_FILE_ERROR): return "file could not be read";
        default: {
            char buf[48];
            std::snprintf(buf, sizeof buf, "WinVerifyTrust error 0x%08lX", static_cast<unsigned long>(hr));
            return buf;
        }
    }
}

bool IsSignatureAbsent(long hr) {
    return hr == static_cast<long>(TRUST_E_NOSIGNATURE) || hr == static_cast<long>(TRUST_E_SUBJECT_FORM_UNKNOWN) ||
           hr == static_cast<long>(TRUST_E_PROVIDER_UNKNOWN);
}

bool IsRevocationOffline(long hr) {
    return hr == static_cast<long>(CERT_E_REVOCATION_FAILURE) || hr == static_cast<long>(CRYPT_E_REVOCATION_OFFLINE) ||
           hr == static_cast<long>(CRYPT_E_NO_REVOCATION_CHECK);
}

long RunTrust(const std::wstring& path, DWORD revoke, DWORD provFlags, std::string* signer) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = revoke;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = provFlags;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    long hr = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    if (signer && wd.hWVTStateData) {
        CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData);
        CRYPT_PROVIDER_SGNR* sg = pd ? WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0) : nullptr;
        CRYPT_PROVIDER_CERT* pc = sg ? WTHelperGetProvCertFromChain(sg, 0) : nullptr;
        if (pc && pc->pCert) {
            wchar_t name[512] = {};
            if (CertGetNameStringW(pc->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512) > 1)
                *signer = Narrow(name);
        }
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    return hr;
}

}  // namespace

AuthenticodeResult VerifyAuthenticode(const std::string& path, RevocationMode mode) {
    AuthenticodeResult r;
    std::wstring wpath = Widen(path);
    long hr = RunTrust(wpath, WTD_REVOKE_WHOLECHAIN, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, &r.signerSubject);
    if (hr != 0 && IsRevocationOffline(hr) && mode == RevocationMode::Soft) {
        // Retry without online revocation; the rest of the chain must still be valid.
        std::string signer;
        long hr2 = RunTrust(wpath, WTD_REVOKE_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL, &signer);
        if (hr2 == 0) {
            r.status = AuthenticodeResult::Status::Valid;
            r.revocationUnchecked = true;
            r.signerSubject = signer;
            r.message = "valid (revocation status could not be checked online)";
            return r;
        }
        hr = hr2;
    }
    r.trustError = hr;
    if (hr == 0) {
        r.status = AuthenticodeResult::Status::Valid;
        r.message = "valid";
    } else if (IsSignatureAbsent(hr)) {
        r.status = AuthenticodeResult::Status::NotSigned;
        r.message = HrText(hr);
    } else {
        r.status = AuthenticodeResult::Status::Invalid;
        r.message = HrText(hr);
    }
    return r;
}

}  // namespace sg
