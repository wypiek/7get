# Security design

SevenGet downloads and runs software, so it is designed around one question:
*how could a package that the user did not intend to run end up being run?*

## Threat model

| Threat | Mitigation |
|--------|------------|
| Network attacker (MITM, malicious Wi-Fi, proxy) | HTTPS only, TLS 1.2+ only, certificate validation never disabled, HTTPS→HTTP redirects refused. Independently of TLS, every package is checked against a SHA-256 from **signed** metadata, so TLS is defence in depth. |
| Compromised download server / mirror / CDN | Package bytes must match the SHA-256 in signed metadata; size is capped by the manifest. |
| Compromised repository web server (metadata) | Metadata is signed offline with ECDSA P-256. The client pins the enrolled key; a different key is rejected as an "unexpected key change". |
| Replay of old, vulnerable metadata (rollback) | Monotonic `sequence`; the highest accepted value is stored in the database (and in the snapshot used for repair) and older metadata is rejected. Re-enrolling never lowers it. |
| Freeze attack (withholding updates forever) | Metadata carries `expires`; installs from expired metadata are refused. |
| Equivocation (two different indexes with the same sequence) | Detected by comparing the accepted index digest. |
| Malicious or buggy manifest content | Strict schema validation; ids/versions/paths/arguments restricted; no shell; no scripts; MSI property denylist; manifests cannot weaken user security settings. |
| Zip-slip / hostile archives | Every entry name is validated (no absolute paths, drive letters, `..`, ADS `:`, device names, symlinks, duplicates) before anything is written; the resolved path must stay inside the target; size and compression-ratio limits. |
| Command injection | Installers are started with `CreateProcessW` using an explicit application path and correctly quoted arguments (`CommandLineToArgvW` rules, verified by tests). `cmd.exe` is never used. Uninstall commands that point at script hosts (`cmd`, `powershell`, `wscript`, `mshta`, `rundll32`, …) are refused. |
| File swapped between verification and execution (TOCTOU) | The verified file is held open with a deny-write/deny-delete share mode and re-hashed under that lock until the installer exits. |
| Deleting software SevenGet did not install | Uninstall uses only recorded ownership: the exact uninstall registry key (and it must still point to the same uninstaller), the MSI ProductCode read from the verified package, or the recorded file list inside SevenGet's own app directory. |
| DLL planting | `SetDefaultDllDirectories(System32)` when available (KB2533623) and `SetDllDirectory("")`. |
| Elevation abuse | SevenGet runs `asInvoker`. Only machine-wide exe/msi installers are elevated, individually, through the normal UAC prompt. |

Out of scope: a compromised repository **signing key** (the repository
operator is trusted for what they sign), a compromised local administrator or
same-user malware, and vulnerabilities in the installed software itself.

## Repository trust

1. `sevenget repo add <url>` fetches `key.pub` (or reads `--key-file`) and the
   signed index, verifies the signature, and **shows the key fingerprint**.
2. The user must confirm the fingerprint interactively, or supply it with
   `--fingerprint` (obtained out of band, e.g. from the operator's website or
   documentation). `--yes` alone is refused – there is no silent
   trust-on-first-use. Downloading `key.pub` over HTTPS from the same server
   provides no security on its own; the fingerprint comparison does.
3. From then on, every `update` and every command that reads metadata
   verifies the cached index again with the pinned key.

**Key rotation** is explicit: the operator publishes the new fingerprint; users
re-enroll with `sevenget repo add <url> --replace` after verifying it.

Cryptography: CNG (`bcrypt.dll`), available since Windows Vista:
`BCRYPT_SHA256_ALGORITHM`, `BCRYPT_ECDSA_P256_ALGORITHM`. `sevenget doctor`
runs known-answer tests, including verifying a signature made by OpenSSL.

## Authenticode

`WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, whole-chain
revocation checking). With `security.revocation=soft` (default) an
unreachable revocation server is tolerated if the rest of the chain is valid,
and this is reported. With `hard` it fails. When a manifest requires a
signature, the signer name can be pinned with `subject`.

Many legitimate Windows 7-compatible packages are **not** Authenticode signed
(7-Zip is an example). For those SevenGet reports "not signed by publisher"
and relies on the SHA-256 from signed metadata. A package with a present but
invalid signature is reported as a warning unless the signature is required.

Windows 7 needs **KB4474419** (SHA-2 code signing support) and current root
certificates (automatic root update or the latest root update package) to
validate many modern signatures. If a required signature fails on Windows 7,
check these first.

## TLS on Windows 7

Windows 7 SP1's WinHTTP does not offer TLS 1.2 by default. SevenGet asks
WinHTTP for TLS 1.2 only (`WINHTTP_OPTION_SECURE_PROTOCOLS`) and fails with a
clear message if the system cannot do it. It never falls back to TLS 1.0/1.1
and never disables certificate validation.

To enable TLS 1.2 for WinHTTP on Windows 7 SP1:

1. Install **KB3140245** (WinHTTP TLS 1.1/1.2 support). It is included in
   later monthly rollups; `sevenget doctor` reports whether WinHTTP accepts
   TLS 1.2.
2. Optionally set the system default for other WinHTTP programs (SevenGet
   does not need this because it requests TLS 1.2 itself):
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`
   `DefaultSecureProtocols` (DWORD) = `0x00000A00` (TLS 1.1 + 1.2), and the same
   under `HKLM\SOFTWARE\Wow6432Node\...` on 64-bit systems. Microsoft's article
   for KB3140245 documents this value.
3. Make sure TLS 1.2 is not disabled under
   `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client`
   (`doctor` checks `Enabled=0`).
4. Keep root certificates current, otherwise servers fail with
   "untrusted certificate authority".

Servers that only offer TLS 1.3 or cipher suites that Windows 7 Schannel does
not implement (for example some ChaCha20-only or ECDSA-P384-only setups)
cannot be reached from Windows 7; SevenGet reports a TLS channel error.

## What SevenGet does **not** do

- It does not make Windows 7 secure. Windows 7 has not received security
  updates since January 2023 (ESU end). SevenGet says so, without blocking
  normal use.
- It does not run arbitrary scripts from repositories – manifests cannot
  contain scripts, only declarative data.
- It does not modify system TLS/registry settings; `doctor` only reports.
