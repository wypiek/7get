// SevenGet - entry point.
#include <windows.h>

#include <string>
#include <vector>

#include "cli/commands.h"
#include "platform/winutil.h"
#include "util/strings.h"

int wmain(int argc, wchar_t** argv) {
    // Do not let Windows show "insert disk" / critical-error dialogs for
    // removable or network paths; report errors instead.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    // DLL search hardening (KB2533623 on Windows 7 provides SetDefaultDllDirectories;
    // resolve it dynamically so the binary still starts without that update).
    typedef BOOL(WINAPI * SetDefaultDllDirectoriesFn)(DWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto setDirs = k32 ? reinterpret_cast<SetDefaultDllDirectoriesFn>(
                             reinterpret_cast<void*>(GetProcAddress(k32, "SetDefaultDllDirectories")))
                       : nullptr;
    if (setDirs) setDirs(0x00000800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */);
    SetDllDirectoryW(L"");

    sg::InstallCtrlHandler();
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(sg::Narrow(argv[i]));
    return sg::RunCli(args);
}
