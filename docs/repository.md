# Running a SevenGet repository

A repository is a static directory served over HTTPS (any web server, GitHub
raw files, S3, …) or a local/UNC directory:

```
key.pub          public key (users verify its fingerprint when enrolling)
index.json       all manifests + sequence / expiry
index.json.sig   ECDSA P-256 signature of index.json
```

## 1. Create a signing key (once, offline)

Windows:
```
sevenget-repotool keygen --private repo.key --public key.pub
```
Linux/macOS (OpenSSL):
```
python3 tools/repotool.py keygen --private repo.key.pem --public key.pub
```
Keep the private key off the web server, ideally on an offline machine.
Publish the printed fingerprint somewhere users can verify independently of
the repository server.

## 2. Write manifests

One JSON file per package in a directory (see
[manifest-schema.md](manifest-schema.md)). For every installer you add:

1. Download the file yourself from the publisher's official location.
2. Compute the SHA-256 (`sevenget-repotool hash file` or `sha256sum`) and
   compare it with any checksum the publisher publishes.
3. Take silent switches and uninstall details **only from vendor
   documentation or source code**, and record the source in `notes`.
4. Set `minWindows` to `6.1` **only if the publisher states Windows 7
   support** for that release. If in doubt, use a higher version – SevenGet
   will then pick an older release that is marked compatible.

Validate: `sevenget-repotool lint manifests\*.json`.

## 3. Build and sign the index

```
sevenget-repotool build --manifests manifests --name my-repo --key repo.key --out site --expires-days 180
python3 tools/repotool.py build --manifests manifests --name my-repo --key repo.key.pem --out site --expires-days 180
```

`--sequence` defaults to the previous `site/index.json` sequence + 1. Every
published change **must** increase the sequence; clients reject older or
conflicting metadata. Re-sign before `expires` even if nothing changed,
otherwise clients stop installing from the repository.

Verify: `sevenget-repotool verify --public site\key.pub site`.

## 4. Publish

Upload the three files. Users enroll with:
```
sevenget repo add https://example.org/sevenget --fingerprint <fingerprint>
```

## Key rotation

1. Generate a new key, build the index with it (sequence must still increase).
2. Publish the new fingerprint through your trusted channel.
3. Users run `sevenget repo add <url> --replace --fingerprint <new>`.
   Until they do, `update` fails with "signed with an unexpected key" – this is
   intentional: SevenGet cannot distinguish a planned rotation from an attack.

## The sample repository in this source tree

`repo/` is a working example (7-Zip and PuTTY). See `repo/README.md` for how
each entry was verified. It is signed with a sample key whose private half is
**not** in the source tree; its metadata expires on 2027-10-28. Fork it and
sign it with your own key for real use.
