# Windows 7 compatibility testing

A successful build is **not** proof that SevenGet runs on Windows 7. This
document separates what has been verified from what still needs a real
Windows 7 SP1 machine or VM.

## What has been run (2026-10-28)

Environment: Linux container, MinGW-w64 GCC 13 (`-win32` thread model,
msvcrt), Wine 9.0 (64-bit only), Wine configured with `winecfg -v win7` so
`RtlGetVersion` reports NT 6.1.7601 SP1. Wine is a reimplementation of the
Windows API, not Windows 7: results below show the code works against the
Win32 API surface, not that every Windows 7 DLL behaves identically.

| Check | x64 | x86 | Result |
|-------|-----|-----|--------|
| Release build, zero compiler warnings (`-Wall -Wextra`) | ✔ | ✔ | pass |
| `tools/check_imports.py`: only Windows 7 DLLs/functions, subsystem 6.1 | ✔ | ✔ | pass (`sevenget.exe`, `sevenget-repotool.exe`, tests) |
| Unit + integration suite `sevenget_tests.exe` (46 tests) | Wine | not run (no 32-bit Wine available) | 46/46 pass on x64 |
| `doctor` (CNG SHA-256/ECDSA KATs, WinHTTP TLS 1.2 option, SQLite integrity) | Wine | – | pass |
| `repo add` of the sample repo with `--fingerprint` | Wine | – | pass |
| Windows 7 version gating: PuTTY 0.85 (marked NT 10.0) skipped, 0.83 selected | Wine (win7 mode) | – | pass |
| Real HTTPS download over WinHTTP (through an HTTP CONNECT proxy) | Wine | – | pass (the.earth.li, www.7-zip.org, GitHub release redirect) |
| PuTTY 0.83 zip: download, SHA-256, Authenticode on 6 binaries (signer pinned), per-user install, `list`, `uninstall` | Wine | – | pass |
| 7-Zip 23.01 MSI install (machine), `outdated`, upgrade to 26.05 (uninstall-first), uninstall | Wine | – | pass |
| 7-Zip 26.05 EXE install (`/S`), ownership via `Uninstall\7-Zip` key, uninstall via `QuietUninstallString` | Wine | – | pass |
| HTTP 404 → exit 4; wrong SHA-256 on a real download → exit 5, file deleted, transaction `failed` | Wine | – | pass |
| `WinVerifyTrust`: valid PuTTY → valid; one byte flipped → "digest mismatch"; 7-Zip → "not signed" | Wine | – | pass |
| Redirected stdout is UTF-8 with CRLF, `--json` documents parse | Wine | – | pass |
| MSVC (VS 2022 v143) build | – | – | **not built locally**; configured in CI (`.github/workflows/build.yml`) |

## What still requires real Windows 7 SP1

Microsoft no longer distributes Windows 7 evaluation VMs; use your own
licensed installation media. Test **both** x86 and x64, as a **standard user**
(not administrator) unless stated, in the original `cmd.exe` console with the
default raster font and with "Lucida Console".

Prepare two snapshots:
- **A – clean SP1**: Windows 7 SP1 with no further updates.
- **B – updated**: SP1 + KB3140245 + KB4474419 + KB2533623 (+ current root
  certificates, e.g. via an up-to-date convenience rollup).

| # | Snapshot | Steps | Expected |
|---|----------|-------|----------|
| 1 | A | `sevenget version`, `sevenget help` | Starts (no missing DLL/entry point dialog); shows "Windows 7 … NT 6.1.7601, SP1" |
| 2 | A | `sevenget doctor` | Windows 7 warning; WinHTTP TLS 1.2 = FAIL with KB3140245 hint; CNG checks OK; exit 1 |
| 3 | A | `sevenget repo add https://raw.githubusercontent.com/wypiek/7get/main/repo --fingerprint …` | Fails with a clear TLS message (exit 4); no fallback to TLS 1.0 |
| 4 | A | `sevenget repo add C:\path\to\7get\repo --fingerprint …` (local copy) | Succeeds (local repositories need no network) |
| 5 | B | `sevenget doctor` | TLS 1.2 OK; exit 0 (WARN for Windows 7 support status) |
| 6 | B | enroll the HTTPS sample repository; `sevenget search`; `sevenget info SimonTatham.PuTTY` | PuTTY 0.83 selected, 0.85 shown incompatible |
| 7 | B | `sevenget install SimonTatham.PuTTY` (standard user) | No UAC prompt; progress bar with speed; 6× Authenticode valid "Simon Tatham"; files in `%LOCALAPPDATA%\SevenGet\apps\SimonTatham.PuTTY` |
| 8 | A | Same as 7 using a local repository copy and `sevenget download` from snapshot B | Record the Authenticode result without KB4474419: either valid, or the install is refused with the KB4474419 / root-certificate hint (never installed with a failed required signature) |
| 9 | B | `sevenget install 7zip.7zip` as standard user | UAC prompt for msiexec; after approval installed; `list` shows machine scope |
| 10 | B | Repeat 9 and click "No" on UAC | Exit 9, nothing recorded, `history` shows `failed` |
| 11 | B | `sevenget install 7zip.7zip --version 23.01`, then `outdated`, `upgrade --all` | 23.01 → 26.05 upgrade |
| 12 | B | `sevenget config set installerPreference exe,msi,zip`, uninstall, install again | EXE backend; uninstall through `QuietUninstallString` |
| 13 | B | Start `PUTTY.EXE`, then `sevenget uninstall SimonTatham.PuTTY` | "files are in use", exit 7, record kept; close PuTTY, retry succeeds |
| 14 | B | Press Ctrl+C during a large download | Download stops, exit 8; re-run resumes (`Range` request) |
| 15 | B | Press Ctrl+C while msiexec runs | SevenGet waits for msiexec and reports the real outcome |
| 16 | B | `sevenget list > out.txt`, `sevenget list --json \| more` | UTF-8 file without color codes; valid JSON |
| 17 | B | Run from a directory and `SEVENGET_HOME` containing spaces and non-ASCII characters | All commands work |
| 18 | B | Kill `sevenget.exe` (Task Manager) during an install, then run `sevenget list` | Warning about an interrupted operation; `history` shows `interrupted` |
| 19 | B | Corrupt `%LOCALAPPDATA%\SevenGet\sevenget.db` (overwrite with zeros), run `sevenget list`, then `sevenget doctor --repair` | Clear database error (exit 10); repair rebuilds from the snapshot |
| 20 | B | Resize the console to 40 columns; `sevenget search` | Tables truncate with `~` instead of wrapping |
| 21 | B | Run `sevenget_tests.exe` (x86 and x64) | All tests pass |

Record results (pass/fail, screenshots of console output) in the release notes.
Until this table has been completed, SevenGet's Windows 7 support should be
described as "built and statically checked for Windows 7 SP1, functionally
tested under Wine; not yet validated on real Windows 7".
