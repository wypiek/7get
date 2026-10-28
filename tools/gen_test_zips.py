#!/usr/bin/env python3
"""Generates the ZIP fixtures in tests/data used by the zip-slip / extraction tests.

Run from the repository root:  python3 tools/gen_test_zips.py
The generated files are committed so the Windows test run needs no Python.
"""
import os
import stat
import zipfile

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "data")


def make(name, entries, symlink=None):
    path = os.path.join(OUT, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for entry, data in entries:
            z.writestr(entry, data)
        if symlink:
            info = zipfile.ZipInfo(symlink[0])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, symlink[1])
    print("wrote", path)


os.makedirs(OUT, exist_ok=True)
make("good.zip", [
    ("app/", b""),
    ("app/tool.exe", b"MZ fake binary for tests\n" * 100),
    ("app/readme \u00e9\u65e5.txt", "unicode name".encode()),
    ("app/sub/dir/config.ini", b"[a]\nb=1\n"),
])
make("slip-dotdot.zip", [("ok.txt", b"x"), ("../evil.txt", b"pwned")])
make("slip-nested.zip", [("a/b/../../../evil.txt", b"pwned")])
make("slip-absolute.zip", [("/windows/evil.txt", b"pwned")])
make("slip-drive.zip", [("C:/evil.txt", b"pwned")])
make("slip-backslash.zip", [("..\\evil.txt", b"pwned")])
make("slip-ads.zip", [("file.txt:hidden", b"pwned")])
make("slip-device.zip", [("dir/CON.txt", b"pwned")])
make("slip-symlink.zip", [("ok.txt", b"x")], symlink=("link", "C:/Windows"))
make("dup-case.zip", [("A.txt", b"1"), ("a.txt", b"2")])
with open(os.path.join(OUT, "not-a-zip.zip"), "wb") as f:
    f.write(b"this is not a zip archive\n" * 10)
# Truncated archive: valid header, cut-off data.
with open(os.path.join(OUT, "good.zip"), "rb") as f:
    data = f.read()
with open(os.path.join(OUT, "truncated.zip"), "wb") as f:
    f.write(data[: len(data) // 2])
