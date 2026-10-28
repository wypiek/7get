# Known limitations

These are deliberate scope limits or open items, not hidden stubs.

## Platform / testing
- **Not yet validated on real Windows 7.** See
  [windows7-testing.md](windows7-testing.md) for exactly what was run (MinGW
  builds, import-table check, full test suite and real package flows under
  Wine in Windows 7 mode) and the checklist that still needs a Windows 7 SP1
  machine.
- The 32-bit test binary was built but not executed (no 32-bit Wine was
  available during development).
- The MSVC build is configured (presets, CI) but was not compiled locally.
- ARM64 installers are rejected by the manifest validator in this version.

## Installation
- **Per-user vs. machine records**: the installation database is per user.
  A machine-wide package installed by one user is listed only for that user;
  another user's SevenGet does not know about it.
- **EXE installers** are run with the vendor's default install location;
  custom install directories are not supported (vendors use incompatible,
  often unquoted `/D=` syntaxes that cannot be passed safely in general).
- **Upgrades with `uninstall-first`** (default for MSI) remove the old version
  before installing the new one. If the new installer then fails, the package
  is not installed any more; SevenGet reports this explicitly and does not
  mark anything as successful.
- **Interactive uninstallers**: if a program registers neither a
  `QuietUninstallString` nor manifest `quietArgs`, its uninstaller window is
  shown.
- **Portable (zip) packages** are not added to `PATH` and no Start-menu
  shortcuts are created; `list --json` / `info` show the install location.
- **Machine-wide zip installs** require running SevenGet from an elevated
  prompt (SevenGet does not re-launch itself elevated).
- Reboot-required results (3010/1641) are reported (exit 12) but SevenGet never
  reboots the machine.
- No automatic rollback of a failed EXE installer – that is up to the vendor
  installer; SevenGet only refuses to record a failed installation.

## Network
- Proxy support: explicit `network.proxy`, Internet Options static proxy, and
  WPAD/PAC via `WinHttpGetProxyForUrl`. Proxies requiring authentication are
  supported only as far as WinHTTP auto-logon (NTLM/Kerberos) handles them.
- TLS 1.3 is requested only on systems whose WinHTTP is known to support it
  (Windows Server 2022 / Windows 11 builds); Windows 7 uses TLS 1.2.
- Downloads are sequential; no parallel downloads or mirrors per package.

## Repositories
- One signing key per repository (no threshold signatures / key hierarchy).
  Key rotation requires users to re-enroll explicitly.
- The sample repository is signed with a sample key whose private key is not
  part of the source tree; it expires on 2027-10-28 and must be re-signed (with
  a new key) by whoever maintains it.
- Package ids are global across repositories: on collisions the
  higher-priority (earlier added) repository wins; there is no
  `--source` selector yet.
