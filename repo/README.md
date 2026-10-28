# SevenGet sample repository

Signed demonstration repository with real, Windows 7-compatible packages.

```
sevenget repo add https://raw.githubusercontent.com/wypiek/7get/main/repo ^
    --fingerprint 14ecfe2261e01ac8809ea8a6275aae15313b719d819c8c705c811c237b320df1
```

(Display form: `14EC FE22 61E0 1AC8 809E A8A6 275A AE15 313B 719D 819C 8C70 5C81 1C23 7B32 0DF1`.)
A local checkout works too: `sevenget repo add C:\src\7get\repo --fingerprint ...`.

| File | Content |
|------|---------|
| `manifests/*.json` | Source manifests |
| `index.json` | Built index, repository `sevenget-sample`, sequence 1, expires 2027-10-28 |
| `index.json.sig` | ECDSA P-256 signature |
| `key.pub` | Sample public key |

The private key of this sample repository is not part of the source tree.
To publish changes you must sign with your own key (and users must enroll
your key); see [docs/repository.md](../docs/repository.md).

## How each entry was verified (2026-10-28)

Every file was downloaded from the URL in the manifest and hashed locally;
sizes and SHA-256 values in the manifests were generated from those files,
not typed by hand.

### 7-Zip (`7zip.7zip`) 26.05 and 23.01 — exe and msi, x86 and x64

- **Windows 7 support:** the official site states "7-Zip works in Windows 11 /
  10 / 8 / 7 / Vista / XP …" (https://www.7-zip.org/).
- **URLs:** exactly as linked from https://www.7-zip.org/download.html
  (26.05 on the GitHub releases of `ip7z/7zip`, 23.01 on `www.7-zip.org/a/`).
- **Silent switches:** 7-Zip FAQ (https://www.7-zip.org/faq.html): exe `/S`,
  msi via `msiexec` quiet mode.
- **Uninstall:** the exe installer writes
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip` with
  `QuietUninstallString = "...\Uninstall.exe" /S`
  (`C/Util/7zipInstall/7zipInstall.c` in the 7-Zip source; `/S` handling in
  `C/Util/7zipUninstall/7zipUninstall.c`). MSI ProductCodes were read from the
  packages with `msiinfo export <msi> Property`.
- **Signatures:** the 7-Zip installers carry no Authenticode signature
  (checked with `osslsigncode`), so `signature.required` is false and the
  SHA-256 from signed metadata is the integrity check.
- **License:** 7-Zip is mostly LGPL-2.1-or-later with BSD-3-Clause parts and
  the unRAR restriction; redistribution of the unmodified installers is
  permitted. SevenGet only links to the publisher's files.

### PuTTY (`SimonTatham.PuTTY`) 0.83 and 0.85 — portable zip, x86 and x64

- **Windows 7 support:** the PuTTY FAQ says official builds aim to support
  Windows versions still in security support, and explicitly that
  "PuTTY 0.83 still runs on Windows XP". 0.83 is therefore marked
  `minWindows 6.1`. No Windows 7 statement exists for 0.85, so 0.85 is marked
  `minWindows 10.0`; Windows 7 systems get 0.83. This demonstrates that
  SevenGet never selects a newer release that is not declared compatible.
- **Hashes:** identical to the vendor's `sha256sums` files for each release
  (`https://the.earth.li/~sgtatham/putty/<version>/sha256sums`).
- **Signatures:** every `.EXE` in the archives is Authenticode-signed by
  "Simon Tatham" (Sectigo Public Code Signing CA R36, verified with
  `osslsigncode`); the manifest requires and pins this signer.
- **License:** MIT.
