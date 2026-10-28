# SevenGet

SevenGet (`sevenget.exe`) is a native command-line package manager for
**Windows 7 SP1** (x86 and x64) that also runs on Windows 8.1, 10 and 11.
It is a single statically linked C++17 executable that uses Win32 APIs only:
no .NET, PowerShell, Python, background service or GUI is needed, and it works
in the original Windows 7 Command Prompt.

```
C:\>sevenget search putty
ID                 NAME   VERSION  ARCH  TYPE  STATUS
SimonTatham.PuTTY  PuTTY  0.83     x64   zip   Available

C:\>sevenget install SimonTatham.PuTTY
Resolving package... PuTTY 0.83 (x64, zip, user) from sevenget-sample
Checking compatibility... OK (Windows NT 6.1 x64; release requires NT 6.1+)
  newer release skipped - 0.85: requires Windows NT 10.0 or later
...
Verifying SHA-256... OK
Authenticode PUTTY.EXE: valid, signed by Simon Tatham
Installation completed successfully.
```

(The output above was captured from a real run under Wine configured as
Windows 7; see [docs/windows7-testing.md](docs/windows7-testing.md) for what
has and has not been tested on real Windows 7.)

> **Windows 7 is unsupported by Microsoft.** It has received no security
> updates since January 2023. SevenGet verifies everything it installs, but it
> cannot make Windows 7 secure. It shows this notice before installs
> (disable with `sevenget config set warnings.windows7 false`).

## Features

| Area | Status |
|------|--------|
| Commands: `help version search info install uninstall update upgrade list outdated download clean doctor repo config history` | Implemented |
| Flags: `--yes --quiet --verbose --json --arch --version --dry-run --no-color --user --machine --force` | Implemented |
| Signed repository metadata (ECDSA P-256 via CNG), explicit key enrollment, rollback / equivocation / expiry protection | Implemented, unit tested |
| HTTPS-only downloads over WinHTTP, TLS 1.2 enforced, resumable, size-capped | Implemented; tested under Wine with real servers |
| SHA-256 verification of every package (file locked against modification while installing) | Implemented, tested |
| Authenticode verification (`WinVerifyTrust`) with optional signer-name pinning | Implemented; tested under Wine |
| Installer backends: **EXE** (vendor silent switches + Uninstall registry key), **MSI** (msiexec + ProductCode), **ZIP** (own safe extraction) | Implemented; all three tested end-to-end under Wine with real 7-Zip / PuTTY packages |
| Version selection: newest release *explicitly marked* compatible with the running Windows version and architecture | Implemented, unit tested |
| Dependencies (`dependencies` in manifests), topological install order, cycle detection | Implemented, unit tested (sample repo has no dependencies) |
| SQLite state database (WAL, `synchronous=FULL`), transaction journal, crash detection, snapshot-based `doctor --repair` | Implemented, tested |
| Per-user installs without administrator rights; UAC elevation only for machine-wide exe/msi installers | Implemented; UAC path needs real Windows (Wine runs as administrator) |
| Console: aligned tables, colors via `SetConsoleTextAttribute` (no ANSI), progress with speed/ETA, Unicode via `WriteConsoleW`, UTF-8 when redirected, Ctrl+C handling | Implemented |

Known limitations are listed in [docs/limitations.md](docs/limitations.md).

## Quick start

1. Download `sevenget.exe` for your architecture (or build it, see
   [docs/building.md](docs/building.md)) and put it in a directory on `PATH`.
2. Run `sevenget doctor`. On Windows 7 it tells you whether TLS 1.2 is usable
   (update **KB3140245** is required; see [docs/security.md](docs/security.md)).
3. Enroll a repository. SevenGet never trusts a repository key silently; it
   shows the key fingerprint and asks you to confirm it, or you pass the
   fingerprint you obtained from the repository operator:

   ```
   sevenget repo add https://raw.githubusercontent.com/wypiek/7get/main/repo ^
       --fingerprint 14ecfe2261e01ac8809ea8a6275aae15313b719d819c8c705c811c237b320df1
   ```

   This is the **sample repository** in [`repo/`](repo/) (7-Zip and PuTTY,
   with metadata verified as described in [repo/README.md](repo/README.md)).
   It is a demonstration repository signed with a sample key; its metadata
   expires on 2027-10-28. Run your own repository for real use (see
   [docs/repository.md](docs/repository.md)).
4. Use it:

   ```
   sevenget search 7zip
   sevenget info 7zip.7zip
   sevenget install SimonTatham.PuTTY            (per-user, no admin rights)
   sevenget install 7zip.7zip                    (machine-wide, UAC prompt)
   sevenget list
   sevenget update && sevenget outdated
   sevenget upgrade --all
   sevenget uninstall SimonTatham.PuTTY
   ```

## Where SevenGet keeps its files

| What | Location |
|------|----------|
| Settings | `%APPDATA%\SevenGet\config.json` |
| Database, snapshot, logs, cache, temp | `%LOCALAPPDATA%\SevenGet\` |
| Per-user portable packages | `%LOCALAPPDATA%\SevenGet\apps\<package-id>` |
| Machine-wide portable packages | `%ProgramFiles%\SevenGet Apps\<package-id>` (elevated prompt) |
| Portable/test mode | set `SEVENGET_HOME` to use one directory for all of the above |

Nothing mutable is stored next to `sevenget.exe` or in Program Files.

## Documentation

- [docs/commands.md](docs/commands.md) – command and flag reference, exit codes, JSON output
- [docs/manifest-schema.md](docs/manifest-schema.md) – package manifest and index format
- [docs/repository.md](docs/repository.md) – running a repository, signing, key rotation
- [docs/security.md](docs/security.md) – threat model, trust design, TLS on Windows 7
- [docs/architecture.md](docs/architecture.md) – source layout and components
- [docs/building.md](docs/building.md) – toolchains, x86/x64 builds, tests, release packaging
- [docs/windows7-testing.md](docs/windows7-testing.md) – what was tested where, and the Windows 7 test plan
- [docs/limitations.md](docs/limitations.md) – known limitations

## License

MIT, see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
