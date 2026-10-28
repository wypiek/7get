#!/usr/bin/env python3
"""Verify that SevenGet executables only import DLLs and functions that exist on
Windows 7 SP1.

Usage:  python3 tools/check_imports.py build/x64/sevenget.exe [more.exe ...]

The PE import table is read directly (no objdump/dumpbin needed), so the check
runs on Linux, macOS and Windows build hosts. It fails when an executable:
  * imports a DLL that is not part of a Windows 7 SP1 installation
    (including api-ms-win-* / ext-ms-win-* API sets, which Windows 7 only
    partially provides),
  * imports a function from the denylist of APIs introduced in Windows 8 or
    later (or only available on Windows 7 through optional updates),
  * declares a subsystem/OS version newer than 6.1.

A passing check is necessary but not sufficient for Windows 7 compatibility;
see docs/windows7-testing.md for the run-time checks that still require a real
Windows 7 SP1 machine or VM.
"""
import struct
import sys

# DLLs present on every Windows 7 SP1 installation that SevenGet may use.
ALLOWED_DLLS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
    "oleaut32.dll", "msvcrt.dll", "winhttp.dll", "bcrypt.dll", "crypt32.dll",
    "wintrust.dll", "msi.dll", "ntdll.dll", "shlwapi.dll", "version.dll",
    "ws2_32.dll", "gdi32.dll", "comctl32.dll", "secur32.dll",
}

# Functions introduced after Windows 7 (or needing optional Windows 7 updates).
DENIED_FUNCTIONS = {
    # kernel32 (Windows 8+)
    "GetSystemTimePreciseAsFileTime", "CreateFile2", "CopyFile2", "GetOverlappedResultEx",
    "GetCurrentThreadStackLimits", "SetThreadDescription", "GetThreadDescription",
    "WaitOnAddress", "WakeByAddressSingle", "WakeByAddressAll", "PrefetchVirtualMemory",
    "VirtualAlloc2", "MapViewOfFile3", "MapViewOfFileNuma2", "CompareObjectHandles",
    "InitializeSynchronizationBarrier", "EnterSynchronizationBarrier", "DeleteSynchronizationBarrier",
    "GetFirmwareType", "IsWow64Process2", "GetProcessMitigationPolicy", "SetProcessMitigationPolicy",
    "GetSystemCpuSetInformation", "SetThreadSelectedCpuSets", "CreatePseudoConsole",
    "ResizePseudoConsole", "ClosePseudoConsole", "GetCurrentPackageId", "GetPackageFamilyName",
    "GetCurrentPackageFullName", "GetPackagePath", "AppPolicyGetProcessTerminationMethod",
    "GetProcessInformation", "SetProcessInformation", "GetThreadInformation", "SetThreadInformation",
    "GetMachineTypeAttributes", "QueryUnbiasedInterruptTimePrecise", "DiscardVirtualMemory",
    "OfferVirtualMemory", "ReclaimVirtualMemory", "GetIntegratedDisplaySize",
    # KB2533623-only on Windows 7 (must be resolved dynamically)
    "SetDefaultDllDirectories", "AddDllDirectory", "RemoveDllDirectory",
    # user32 / shcore DPI APIs (Windows 8.1 / 10)
    "GetDpiForWindow", "GetDpiForSystem", "SetProcessDpiAwarenessContext", "SetThreadDpiAwarenessContext",
    "AdjustWindowRectExForDpi", "GetSystemMetricsForDpi", "EnableNonClientDpiScaling",
    # bcrypt (Windows 8 / 10)
    "BCryptHash", "BCryptKeyDerivation", "BCryptCreateMultiHash", "BCryptProcessMultiOperations",
    # winhttp (Windows 8+)
    "WinHttpCreateProxyResolver", "WinHttpGetProxyForUrlEx", "WinHttpGetProxyResult",
    "WinHttpFreeProxyResult", "WinHttpResetAutoProxy", "WinHttpWebSocketCompleteUpgrade",
    "WinHttpWebSocketSend", "WinHttpWebSocketReceive", "WinHttpWebSocketClose",
    "WinHttpWebSocketShutdown", "WinHttpWebSocketQueryCloseStatus", "WinHttpQueryConnectionGroup",
    "WinHttpSetProxySettingsPerUser", "WinHttpReadDataEx",
    # WinRT
    "RoInitialize", "RoUninitialize", "WindowsCreateString", "WindowsDeleteString",
    "RoGetActivationFactory",
}


def rva_to_offset(sections, rva):
    for (va, vsize, raw, rawsize) in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rva - va + raw
    raise ValueError("RVA 0x%x not in any section" % rva)


def read_cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace")


def parse_imports(path):
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, nsec = struct.unpack_from("<HH", data, pe + 4)
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    os_major, os_minor = struct.unpack_from("<HH", data, opt + 40)
    sub_major, sub_minor = struct.unpack_from("<HH", data, opt + 48)
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dd = opt + (112 if is64 else 96)
    imp_rva, imp_size = struct.unpack_from("<II", data, dd + 8)
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        s = sec_off + i * 40
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, s + 8)
        sections.append((va, vsize, raw, rawsize))
    imports = {}
    off = rva_to_offset(sections, imp_rva)
    while True:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if name_rva == 0:
            break
        dll = read_cstr(data, rva_to_offset(sections, name_rva)).lower()
        thunk = rva_to_offset(sections, oft or ft)
        funcs = []
        while True:
            if is64:
                v = struct.unpack_from("<Q", data, thunk)[0]
                ordinal = v & (1 << 63)
                thunk += 8
            else:
                v = struct.unpack_from("<I", data, thunk)[0]
                ordinal = v & (1 << 31)
                thunk += 4
            if v == 0:
                break
            if ordinal:
                funcs.append("#%d" % (v & 0xFFFF))
            else:
                funcs.append(read_cstr(data, rva_to_offset(sections, v & 0x7FFFFFFF) + 2))
        imports.setdefault(dll, []).extend(funcs)
        off += 20
    info = {
        "machine": {0x14C: "x86", 0x8664: "x64"}.get(machine, hex(machine)),
        "os_version": (os_major, os_minor),
        "subsystem_version": (sub_major, sub_minor),
        "subsystem": {3: "console", 2: "gui"}.get(subsystem, str(subsystem)),
    }
    return info, imports


def check(path, verbose):
    info, imports = parse_imports(path)
    problems = []
    if info["subsystem_version"] > (6, 1):
        problems.append("subsystem version %d.%d is newer than 6.1" % info["subsystem_version"])
    if info["os_version"] > (6, 1):
        problems.append("OS version field %d.%d is newer than 6.1" % info["os_version"])
    total = 0
    for dll, funcs in sorted(imports.items()):
        total += len(funcs)
        if dll.startswith("api-ms-win-") or dll.startswith("ext-ms-win-"):
            problems.append("imports API set %s (not reliably available on Windows 7)" % dll)
        elif dll not in ALLOWED_DLLS:
            problems.append("imports %s, which is not in the Windows 7 allowlist" % dll)
        for f in funcs:
            if f in DENIED_FUNCTIONS:
                problems.append("imports %s!%s (not available on Windows 7 SP1)" % (dll, f))
    print("%s: %s %s subsystem %d.%d, %d DLLs, %d functions" % (
        path, info["machine"], info["subsystem"], info["subsystem_version"][0],
        info["subsystem_version"][1], len(imports), total))
    if verbose:
        for dll, funcs in sorted(imports.items()):
            print("  %s: %s" % (dll, ", ".join(sorted(funcs))))
    for p in problems:
        print("  FAIL: " + p)
    if not problems:
        print("  OK: no Windows 8+ imports found")
    return not problems


def main(argv):
    verbose = "-v" in argv
    files = [a for a in argv if a != "-v"]
    if not files:
        print(__doc__)
        return 2
    ok = all([check(f, verbose) for f in files])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
