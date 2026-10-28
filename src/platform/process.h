// SevenGet - process creation without a shell.
//
// Installers are started with CreateProcessW (or ShellExecuteExW "runas" when
// elevation is required) using an explicit application path and a command
// line built by QuoteArgument. cmd.exe is never involved, so shell
// metacharacters in arguments have no special meaning.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sg {

// Quotes one argument so that CommandLineToArgvW / the MSVC CRT parse it back
// to exactly the same string (backslash/quote rules per MSDN
// "Parsing C++ command-line arguments").
std::string QuoteArgument(const std::string& arg);
std::string BuildCommandLine(const std::string& exe, const std::vector<std::string>& args);

// Splits a command line the way CommandLineToArgvW does (used for recorded
// UninstallString values).
std::vector<std::string> SplitCommandLine(const std::string& cmdline);

struct ProcessResult {
    bool started = false;
    uint32_t exitCode = 0;
    uint32_t startError = 0;     // Win32 error if !started
    bool elevated = false;       // started through UAC
    bool cancelledWait = false;  // Ctrl+C was pressed while waiting (process kept running to completion)
};

enum class Elevation {
    Never,         // CreateProcess only
    IfRequired,    // CreateProcess; on ERROR_ELEVATION_REQUIRED retry with "runas"
    Always,        // ShellExecuteEx "runas" (no-op prompt if already elevated)
};

// Runs exe with args, waits for exit. The exe path must be absolute.
// onCancelNotice is invoked once if Ctrl+C is pressed while waiting; the
// child is NOT terminated (killing an installer midway can corrupt the
// installation), SevenGet waits for it and then reports the cancellation.
ProcessResult RunProcess(const std::string& exe, const std::vector<std::string>& args, Elevation elevation,
                         const std::string& workingDir = {}, const std::function<void()>& onCancelNotice = {});

// Same as RunProcess but with a pre-built argument string (everything after
// argv[0]). Used for msiexec, whose PROPERTY="value" syntax does not follow
// the CRT quoting rules.
ProcessResult RunProcessRaw(const std::string& exe, const std::string& argString, Elevation elevation,
                            const std::string& workingDir = {}, const std::function<void()>& onCancelNotice = {});

// Quotes a value for msiexec property syntax: NAME="va""lue".
std::string MsiPropertyArg(const std::string& name, const std::string& value);

}  // namespace sg
