# Command reference

```
sevenget <command> [arguments] [options]
```

Options may appear anywhere on the command line. `--name=value` and
`--name value` are equivalent. `--` ends option parsing (useful for search
terms starting with `-`). Arguments containing spaces must be quoted the usual
Command Prompt way (`"C:\My Repo"`); non-ASCII arguments are fully supported
(SevenGet uses `wmain`/UTF-16 internally).

## Global options

| Option | Meaning |
|--------|---------|
| `--help`, `-h` | Help for SevenGet or for the given command (`sevenget install --help`) |
| `--version` | Without a command: print the SevenGet version. After a command: select a package version (`install 7zip.7zip --version 23.01`) |
| `--yes`, `-y` | Do not ask for confirmation. Required for changes when stdin is not a console or with `--json` |
| `--quiet`, `-q` | Only results and errors |
| `--verbose` | Extra diagnostic output on stderr |
| `--json` | Print one JSON document on stdout (progress/status go to stderr and are suppressed) |
| `--arch x86\|x64\|auto` | Package architecture (default: config `arch`, `auto` = native first, then x86 on x64 Windows) |
| `--user` / `--machine` | Per-user or machine-wide installation (default: config `scope`; `auto` prefers per-user when the package supports it) |
| `--dry-run` | Show the plan, change nothing (no download either) |
| `--no-color` | No console colors (also honoured: `NO_COLOR` environment variable, config `color`) |
| `--force` | `install`: reinstall even if installed. `upgrade --version`: allow a downgrade. `uninstall`: ignore installed dependents |

## Commands

### `help [command]`, `version`
`version` prints the SevenGet version, build architecture/compiler and the
detected Windows version (read with `RtlGetVersion`, so it is not affected by
compatibility shims).

### `search [query]`
Searches id, name, tags, description and publisher of all enabled
repositories (no query lists everything). For each package the newest release
compatible with this system is shown; `STATUS` is `Available`, `Installed`,
`Upgradable (old)` or `Incompatible`. Exit code 3 when nothing matches.

### `info <package>`
Package details plus a table of **every** release and installer with its
Windows requirement, scope, signature requirement and whether it is
compatible with this system. The installer SevenGet would choose is marked `*`.

### `install <package>`
Workflow (each step is printed): resolve → compatibility → dependencies →
metadata check → permission check → plan → confirmation → download →
SHA-256 → Authenticode → install → verify → record → clean up.

- Without `--version`, the newest release explicitly declared compatible with
  this Windows version and architecture is chosen. Newer releases that are not
  compatible are listed as skipped, never installed.
- With `--version`, exactly that release is used or the command fails
  (exit 11 if it is not compatible).
- Already installed (same scope): exit 0 with a hint to use `upgrade`.

### `uninstall <package>`
Removes only what SevenGet recorded at install time:
- **exe**: runs the program's own uninstaller from the exact `Uninstall`
  registry key named by the manifest, after checking the key still points to
  the same uninstaller SevenGet saw at install time.
- **msi**: `msiexec /x {ProductCode} /qn`.
- **zip**: deletes the recorded files inside SevenGet's app directory; files
  you created there are left alone. Fails without deleting anything if a file
  is in use.

If the program was already removed outside SevenGet, the record is dropped
with a warning. If the uninstaller fails, the record is kept.

### `update`
Downloads `index.json` and `index.json.sig` of every enabled repository,
verifies signature, key, sequence (no rollback) and expiry, then atomically
switches to the new metadata. Failures leave the previous metadata in place.

### `upgrade <package>` / `upgrade --all`
Upgrades to the newest compatible release, keeping the installed scope,
architecture and (when possible) installer type. MSI upgrades remove the old
product first (`upgradeBehavior: uninstall-first`); exe installers install over
the old version; zip packages are swapped in atomically and user-created files
in the app directory are carried over.

### `list`
Packages installed by SevenGet, with a live presence check (`Missing` means
it was removed outside SevenGet).

### `outdated`
Installed packages for which a newer compatible release exists.

### `download <package> [--output DIR]`
Downloads and verifies (SHA-256 and Authenticode) without installing, saving
`<id>-<version>-<arch>.<ext>` to `DIR` (default: current directory).

### `clean [--all]`
Removes cached downloads (including partial downloads) and temporary files.
`--all` also removes cached repository metadata (run `update` afterwards).

### `doctor [--repair]`
Checks the OS, CNG SHA-256 and ECDSA (known-answer tests, including an
OpenSSL-generated signature), WinHTTP TLS 1.2 support and the Windows 7 TLS
registry configuration, the data directory, SQLite `integrity_check`,
repository expiry, and interrupted operations. `--repair` moves a corrupted
database aside and rebuilds it from `installed-snapshot.json`.
Exit code 1 if any check FAILs.

### `history`
The last 50 install/upgrade/uninstall transactions with their final state
(`succeeded`, `failed`, `cancelled`, `interrupted`, `reboot-required`).

### `repo list | add <url> | remove <name>`
- `repo add <url> [--name N] [--key-file FILE] [--fingerprint FP] [--replace] [--yes]`
  - `<url>` is an `https://` base URL or an absolute local/UNC directory.
    `http://` is refused.
  - The key is read from `--key-file` or fetched from `<url>/key.pub`, then
    its SHA-256 fingerprint is displayed. You must confirm it interactively
    or pass `--fingerprint` (spaces/colons ignored). `--yes` without
    `--fingerprint` is refused: there is no silent trust-on-first-use.
  - The signed index is downloaded and verified before anything is stored.
  - `--replace` re-enrolls an existing repository (e.g. after a planned key
    rotation). The rollback watermark is never lowered.
- `repo remove <name>` forgets the repository and its key. Installed packages
  stay installed and remain uninstallable.

### `config list | get <key> | set <key> <value>`

| Key | Default | Values |
|-----|---------|--------|
| `arch` | `auto` | `auto`, `x86`, `x64` |
| `scope` | `auto` | `auto`, `user`, `machine` |
| `color` | `auto` | `auto`, `always`, `never` |
| `installerPreference` | `msi,exe,zip` | order of installer types when a release offers several |
| `network.proxy` | *(empty)* | `host:port`; empty = Internet Options proxy / WPAD / PAC |
| `network.timeoutSeconds` | `60` | 5..3600 |
| `network.checkRevocation` | `false` | check TLS server certificate revocation |
| `cache.keepDownloads` | `false` | keep verified installers after installing |
| `security.requireAuthenticode` | `false` | refuse any installer without a valid Authenticode signature |
| `security.revocation` | `soft` | Authenticode revocation: `soft` tolerates an unreachable revocation server, `hard` fails |
| `warnings.windows7` | `true` | show the Windows 7 end-of-support notice |

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | ok | Success (also "already installed", "up to date") |
| 1 | error | General / unexpected error; `doctor` found a failure |
| 2 | usage | Invalid arguments, or confirmation needed but not possible |
| 3 | not-found | Package, version, repository or file not found; `search` found nothing |
| 4 | network | Download failed, TLS failure, server error |
| 5 | integrity | SHA-256 mismatch, Authenticode failure, unsafe archive, size mismatch |
| 6 | trust | Repository signature invalid, unexpected key, rollback, expired metadata |
| 7 | installer-failed | Installer/uninstaller returned failure, or post-install verification failed |
| 8 | cancelled | User declined or pressed Ctrl+C |
| 9 | permission | Elevation refused or administrator rights required |
| 10 | database | Local database error or corruption |
| 11 | incompatible | No release compatible with this Windows version/architecture |
| 12 | reboot-required | Succeeded; Windows must be restarted to finish |
| 13 | busy | Another SevenGet operation or Windows Installer transaction is running |

## JSON output

With `--json`, stdout contains exactly one JSON object (UTF-8, no colors):

```json
{
  "command": "list",
  "installed": [ { "id": "SimonTatham.PuTTY", "version": "0.83", "scope": "user", "present": true, ... } ],
  "ok": true,
  "exitCode": 0,
  "warnings": [ "..." ]
}
```

On failure `ok` is false and an `error` object is present:
`{"code": 6, "kind": "trust", "message": "...", "hint": "..."}`.
Commands that change the system require `--yes` together with `--json`.

## Ctrl+C

- During downloads: the download stops, the partial file is kept and resumed
  next time; nothing is installed (exit 8).
- While an installer runs: SevenGet does **not** kill it (that can corrupt the
  installation); it waits, records the real outcome, and reports the
  cancellation. A second Ctrl+C terminates SevenGet immediately; the
  transaction is then reported as `interrupted` on the next run.
