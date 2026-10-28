# Architecture

```
src/
  main.cpp                 wmain, DLL search hardening, Ctrl+C handler
  cli/
    args.*                 argument parser (flags, --x=y, --, validation)
    commands.*             dispatcher, help, search/info/list/outdated/history, install/upgrade/uninstall/download entry points, JSON envelope
    cmd_system.cpp         repo, config, update, clean, doctor
    context.h              per-invocation state (config, DB, repositories, lock)
  core/
    manifest.*             manifest model + strict validation
    resolver.*             version / compatibility / dependency resolution
    repository.*           signed index verification (pure function), enrollment, update, cache
    database.*             SQLite schema, records, transaction journal, snapshot
    config.*               config.json keys and validation
  install/
    engine.*               install/upgrade/uninstall/download workflow, verification, journaling
    backend.*              backend interface, exit-code policy
    exe_backend.cpp        vendor setup.exe + Uninstall registry key ownership
    msi_backend.cpp        msiexec + ProductCode ownership
    zip_backend.cpp        portable apps: staging, atomic swap, file ownership
    zip_extract.*          safe ZIP extraction (miniz inflate only)
  platform/
    winutil.*              OS info (RtlGetVersion), paths, atomic files, registry, lock, Ctrl+C
    process.*              CreateProcessW / ShellExecuteExW(runas), argument quoting
    http.*                 WinHTTP client (TLS 1.2, proxy, resume, redirects)
    crypto.*               CNG SHA-256, ECDSA P-256
    authenticode.*         WinVerifyTrust wrapper
    console.*              console output, colors, progress, prompts, tables
  util/
    json.*, strings.*, version.*, log.*, error.h
tools/
  repotool/                sevenget-repotool.exe (keygen, lint, build, verify, hash)
  repotool.py              same repository format via OpenSSL (Linux/macOS)
  check_imports.py         Windows 7 import-table verification
  gen_test_zips.py         test fixtures
third_party/               SQLite amalgamation, miniz
repo/                      sample signed repository
tests/                     unit + integration tests
```

## Data flow of `install`

```
RepositoryManager::LoadAll  -> VerifyIndex (signature, key pin, sequence, expiry, manifests)
ResolvePackage              -> newest release with a compatible installer
ResolveDependencies         -> ordered plan
Engine::CheckPermissions    -> per-user / UAC / refuse
confirmation
Engine::ExecuteInstall
   Database::StartTransaction ('started')
   FetchVerified            -> HttpDownloadFile (.part, resume) -> lock -> SHA-256 -> Authenticode
   re-hash under lock
   InstallerBackend::Install -> process + post-install verification -> ownership JSON
   Database::PutInstalled + FinishTransaction (one SQLite transaction)
   snapshot, temp cleanup
```

## Extending

- **New installer type** (e.g. Inno Setup with registry ownership variants, or
  MSIX on newer Windows): add an `InstallerType`, validation rules in
  `manifest.cpp`, a backend implementing `InstallerBackend`, and register it
  in `CreateBackend`. The engine and database do not need changes; the backend
  owns its `uninstall` JSON.
- **New package source**: repositories are directories with three files, so a
  new mirror is just another URL. Different transports (e.g. SMB, already
  supported via UNC paths) plug into `RepositoryManager::FetchFile`.
- **Schema evolution**: index `schema` is checked; unknown manifest fields are
  rejected, so new fields require a client update before repositories use them.
