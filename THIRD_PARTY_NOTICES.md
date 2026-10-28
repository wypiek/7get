# Third-party notices

SevenGet statically links the following components. Both are vendored
unmodified under `third_party/`.

## SQLite 3.54.1

- Source: `sqlite-amalgamation-3540100.zip` from https://www.sqlite.org/download.html
- Integrity: SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`,
  matching the value published on the SQLite download page (checked when vendoring).
- License: public domain. From the source header:

```
The author disclaims copyright to this source code.  In place of
a legal notice, here is a blessing:

   May you do good and not evil.
   May you find forgiveness for yourself and forgive others.
   May you share freely, never taking more than you give.
```

## miniz 3.0.2

- Source: `miniz-3.0.2.zip` from https://github.com/richgel999/miniz/releases/tag/3.0.2
  (SHA-256 of the release archive: `ada38db0b703a56d3dd6d57bf84a9c5d664921d870d8fea4db153979fb5332c5`)
- Used only for DEFLATE decompression of ZIP packages; all path handling and
  safety checks are SevenGet's own (`src/install/zip_extract.cpp`).
- License: MIT

```
Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
