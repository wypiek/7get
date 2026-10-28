#!/usr/bin/env python3
"""SevenGet repository tool for Linux/macOS hosts (uses the `openssl` CLI).

Produces exactly the same repository format as sevenget-repotool.exe:

  keygen  --private key.pem --public key.pub
  build   --manifests DIR --name REPO --key key.pem --out DIR [--sequence N] [--expires-days D]
  verify  --public key.pub DIR
  fingerprint key.pub

Repository layout written by `build`:
  index.json      schema 1 index with all manifests, sequence, generated, expires
  index.json.sig  {"format": "sevenget-sig-v1", "algorithm": "ecdsa-p256-sha256",
                   "keyFingerprint": <sha256 of public point>, "signature": <hex r||s>}
  key.pub         "sevenget-pubkey-v1 ecdsa-p256 <hex 04||X||Y>"

Manifest validation is only structural here; run `sevenget-repotool lint` on
Windows (or under Wine) for the full validation the client applies.
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile


def run(args, data=None):
    p = subprocess.run(args, input=data, capture_output=True)
    if p.returncode != 0:
        sys.exit("openssl failed: " + p.stderr.decode(errors="replace"))
    return p.stdout


def public_point(private_pem):
    der = run(["openssl", "ec", "-in", private_pem, "-pubout", "-outform", "DER"])
    point = der[-65:]
    if point[0] != 4:
        sys.exit("unexpected public key encoding")
    return point


def der_to_raw(der):
    # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    assert der[0] == 0x30
    i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        n = der[i + 1]
        v = der[i + 2:i + 2 + n].lstrip(b"\0")
        out += v.rjust(32, b"\0")
        i += 2 + n
    return out


def raw_to_der(raw):
    def integer(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + bytes([len(b)]) + b
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def fingerprint(point):
    return hashlib.sha256(point).hexdigest()


def pub_text(point):
    return "sevenget-pubkey-v1 ecdsa-p256 " + point.hex() + "\n"


def parse_pub(text):
    parts = text.split()
    if len(parts) != 3 or parts[0] != "sevenget-pubkey-v1" or parts[1] != "ecdsa-p256":
        sys.exit("not a SevenGet public key")
    point = bytes.fromhex(parts[2])
    if len(point) != 65 or point[0] != 4:
        sys.exit("malformed public key")
    return point


def point_to_pem(point):
    # SubjectPublicKeyInfo for id-ecPublicKey / prime256v1
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    der = prefix + point
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as f:
        f.write(der)
        path = f.name
    pem = run(["openssl", "ec", "-pubin", "-inform", "DER", "-in", path])
    os.unlink(path)
    return pem


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_keygen(a):
    if os.path.exists(a.private):
        sys.exit(a.private + " exists; refusing to overwrite")
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", a.private])
    os.chmod(a.private, 0o600)
    point = public_point(a.private)
    open(a.public, "w").write(pub_text(point))
    print("fingerprint:", fingerprint(point))


def cmd_build(a):
    point = public_point(a.key)
    seq = a.sequence
    old = os.path.join(a.out, "index.json")
    if seq is None:
        seq = 1
        if os.path.exists(old):
            seq = json.load(open(old, encoding="utf-8"))["sequence"] + 1
    pkgs = []
    for name in sorted(os.listdir(a.manifests)):
        if name.lower().endswith(".json"):
            with open(os.path.join(a.manifests, name), encoding="utf-8") as f:
                pkgs.append(json.load(f))
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    index = {
        "schema": 1,
        "repository": a.name,
        "sequence": seq,
        "generated": utc(now),
        "expires": utc(now + a.expires_days * 86400),
        "packages": pkgs,
    }
    text = (json.dumps(index, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    der = run(["openssl", "dgst", "-sha256", "-sign", a.key], data=text)
    sig = {
        "format": "sevenget-sig-v1",
        "algorithm": "ecdsa-p256-sha256",
        "keyFingerprint": fingerprint(point),
        "signature": der_to_raw(der).hex(),
    }
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, "index.json"), "wb").write(text)
    open(os.path.join(a.out, "index.json.sig"), "w").write(json.dumps(sig, indent=2) + "\n")
    open(os.path.join(a.out, "key.pub"), "w").write(pub_text(point))
    print("wrote %s: %d packages, sequence %d, expires %s" % (a.out, len(pkgs), seq, index["expires"]))
    print("fingerprint:", fingerprint(point))
    cmd_verify(argparse.Namespace(public=os.path.join(a.out, "key.pub"), dir=a.out))


def cmd_verify(a):
    point = parse_pub(open(a.public).read())
    text = open(os.path.join(a.dir, "index.json"), "rb").read()
    sig = json.load(open(os.path.join(a.dir, "index.json.sig")))
    if sig.get("keyFingerprint") != fingerprint(point):
        sys.exit("FAIL: signed with a different key")
    with tempfile.NamedTemporaryFile(delete=False) as kf, tempfile.NamedTemporaryFile(delete=False) as sf:
        kf.write(point_to_pem(point))
        sf.write(raw_to_der(bytes.fromhex(sig["signature"])))
    p = subprocess.run(["openssl", "dgst", "-sha256", "-verify", kf.name, "-signature", sf.name],
                       input=text, capture_output=True)
    os.unlink(kf.name)
    os.unlink(sf.name)
    if p.returncode != 0:
        sys.exit("FAIL: signature does not verify")
    idx = json.loads(text)
    print("OK: repository %s, sequence %d, %d packages, expires %s" % (
        idx["repository"], idx["sequence"], len(idx["packages"]), idx["expires"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", required=True)
    k.add_argument("--public", required=True)
    b = sub.add_parser("build")
    b.add_argument("--manifests", required=True)
    b.add_argument("--name", required=True)
    b.add_argument("--key", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--sequence", type=int)
    b.add_argument("--expires-days", type=int, default=180)
    v = sub.add_parser("verify")
    v.add_argument("--public", required=True)
    v.add_argument("dir")
    f = sub.add_parser("fingerprint")
    f.add_argument("pub")
    a = ap.parse_args()
    if a.cmd == "keygen":
        cmd_keygen(a)
    elif a.cmd == "build":
        cmd_build(a)
    elif a.cmd == "verify":
        cmd_verify(a)
    else:
        print(fingerprint(parse_pub(open(a.pub).read())))


if __name__ == "__main__":
    main()
