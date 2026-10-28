# Manifest and repository index schema

Manifests are UTF-8 JSON. The parser is strict: duplicate keys, trailing
commas, comments, invalid UTF-8 and **unknown fields** are rejected (so a typo
such as `"sha265"` cannot silently disable a check). The validator is
`src/core/manifest.cpp`; run `sevenget-repotool lint <file>` to check a manifest
with exactly the rules the client applies.

## Package manifest

```json
{
  "id": "SimonTatham.PuTTY",
  "name": "PuTTY",
  "publisher": "Simon Tatham",
  "description": "SSH and Telnet client ...",
  "license": "MIT",
  "homepage": "https://www.chiark.greenend.org.uk/~sgtatham/putty/",
  "tags": ["ssh", "telnet"],
  "releases": [ { "version": "0.83", "installers": [ ... ] } ]
}
```

| Field | Required | Rules |
|-------|----------|-------|
| `id` | yes | 1–100 chars `[A-Za-z0-9._-]`, starts/ends alphanumeric, no `..`, not a DOS device name (`CON`, `NUL`, `COM1`…). Case-insensitive identity. Used as a directory name. |
| `name`, `publisher`, `description` | yes | Non-empty strings, no control characters |
| `license` | no | String |
| `homepage` | no | `https://` URL |
| `tags` | no | Array of strings |
| `releases` | yes | Non-empty array of releases |

## Release

| Field | Required | Rules |
|-------|----------|-------|
| `version` | yes | `[0-9A-Za-z.+-]`, ≤64 chars, starts alphanumeric, no `..`. Unique per package. |
| `releaseDate` | no | `YYYY-MM-DD`, informational |
| `dependencies` | no | `[{"id": "Other.Package", "minVersion": "1.2"}]` – installed first, from the same set of repositories |
| `installers` | yes | Non-empty array |

### Version ordering
Numeric components compare numerically (`24.9 < 24.10`), text components
case-insensitively; missing components count as 0 (`1.0 == 1.0.0`); a `-`
suffix is a pre-release (`1.0-rc1 < 1.0`); `+build` metadata is ignored.

## Installer

| Field | Required | Rules |
|-------|----------|-------|
| `arch` | yes | `x86` or `x64` |
| `type` | yes | `exe`, `msi` or `zip` – each handled by its own backend |
| `url` | yes | `https://` only. Redirects to `http://` are refused. |
| `sha256` | yes | 64 hex chars; the whole file is verified before use |
| `size` | no (recommended) | Exact size in bytes; downloads larger than this are aborted |
| `minWindows` | yes | NT version the publisher **explicitly** supports, e.g. `"6.1"` (Windows 7), `"6.3"` (8.1), `"10.0"` |
| `maxWindows` | no | Highest supported NT version |
| `scope` | yes | `["user"]`, `["machine"]` or both – what the installer really supports |
| `silentArgs` | exe: yes; msi: optional; zip: forbidden | exe: literal argument tokens from the vendor's documentation (each is quoted correctly, never passed through a shell, `"` and control characters are forbidden). msi: only `PUBLICPROPERTY=value` tokens; `TRANSFORMS`, `PATCH`, `REBOOT`, `ALLUSERS`, `MSIINSTALLPERUSER`, `ACTION` are reserved |
| `successExitCodes` | no | Default `[0]` |
| `rebootExitCodes` | no | Default msi `[3010, 1641]`, otherwise none |
| `productCode` | msi: no | Expected `{GUID}`; the ProductCode is always read from the verified MSI and must match if given |
| `upgradeBehavior` | no | `install-over` (default exe) or `uninstall-first` (default msi) |
| `uninstall` | yes | See below |
| `signature` | no | See below |
| `notes` | no | Compatibility evidence / sources (shown by `info`) |

### `uninstall`

| type | `strategy` | Other fields |
|------|------------|--------------|
| exe | `registry` | `registryKey`: exact subkey name under `...\CurrentVersion\Uninstall` that the installer creates (single key name, no `\`). `quietArgs`: arguments appended to `UninstallString` when the program does not register a `QuietUninstallString`. |
| msi | `msi` | – (ProductCode is recorded at install time) |
| zip | `files` | – (extracted file list is recorded) |

### `signature`

```json
"signature": { "required": true, "subject": "Simon Tatham", "files": ["PUTTY.EXE"] }
```

- `required`: installer (exe/msi) or the listed files (zip) must have a valid
  Authenticode signature, otherwise installation is refused.
- `subject`: expected signer (certificate simple display name, case-insensitive).
- `files`: zip only – archive entries to verify after extraction.

When `required` is false SevenGet still checks and reports the signature. A
manifest can only make verification stricter; the user setting
`security.requireAuthenticode=true` makes it mandatory for all packages.

### Compatibility rule
An installer is compatible when `minWindows <= running NT version <= maxWindows`
and its `arch` can run on the system (x64 Windows: x64 then x86; x86 Windows:
x86 only). The newest release with a compatible installer is selected. Only
mark `minWindows: "6.1"` when the publisher states Windows 7 support – see
`repo/manifests/` for examples with the evidence recorded in `notes`.

## Repository index (`index.json`)

```json
{
  "schema": 1,
  "repository": "sevenget-sample",
  "sequence": 1,
  "generated": "2026-10-28T07:35:54Z",
  "expires": "2027-10-28T07:35:54Z",
  "packages": [ <manifest>, ... ]
}
```

| Field | Rules |
|-------|-------|
| `schema` | `1` |
| `repository` | Repository name (package-id rules, ≤40 chars). Must stay the same. |
| `sequence` | Positive integer, **must increase with every published change** (rollback protection) |
| `generated`, `expires` | UTC `YYYY-MM-DDTHH:MM:SSZ`; clients refuse to install from expired metadata |
| `packages` | Manifests. Invalid manifests are skipped with a warning; duplicate ids keep the first |

## Signature (`index.json.sig`)

```json
{
  "format": "sevenget-sig-v1",
  "algorithm": "ecdsa-p256-sha256",
  "keyFingerprint": "<sha256 of the 65-byte public point, hex>",
  "signature": "<64-byte r||s, hex>"
}
```

The signature covers the exact bytes of `index.json`.

## Public key (`key.pub`)

```
sevenget-pubkey-v1 ecdsa-p256 04<X 32 bytes><Y 32 bytes>   (hex)
```

The fingerprint users confirm is the SHA-256 of the 65-byte point.
