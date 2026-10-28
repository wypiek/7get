#include "platform/process.h"

#include <windows.h>
#include <shellapi.h>

#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

std::string QuoteArgument(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos) return arg;
    std::string out = "\"";
    for (size_t i = 0;; ++i) {
        size_t backslashes = 0;
        while (i < arg.size() && arg[i] == '\\') { ++i; ++backslashes; }
        if (i == arg.size()) {
            // Double trailing backslashes so the closing quote is not escaped.
            out.append(backslashes * 2, '\\');
            break;
        }
        if (arg[i] == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out += '"';
        } else {
            out.append(backslashes, '\\');
            out += arg[i];
        }
    }
    out += '"';
    return out;
}

std::string BuildCommandLine(const std::string& exe, const std::vector<std::string>& args) {
    // argv[0] cannot contain quotes on Windows; always quote it.
    std::string cmd = "\"" + exe + "\"";
    for (const auto& a : args) {
        cmd += ' ';
        cmd += QuoteArgument(a);
    }
    return cmd;
}

std::vector<std::string> SplitCommandLine(const std::string& cmd) {
    std::vector<std::string> out;
    size_t i = 0, n = cmd.size();
    // argv[0]: quotes toggle, no escapes (CommandLineToArgvW rule).
    while (i < n && (cmd[i] == ' ' || cmd[i] == '\t')) ++i;
    if (i < n) {
        std::string a;
        bool inq = false;
        for (; i < n; ++i) {
            char c = cmd[i];
            if (c == '"') { inq = !inq; continue; }
            if (!inq && (c == ' ' || c == '\t')) break;
            a += c;
        }
        out.push_back(a);
    }
    for (;;) {
        while (i < n && (cmd[i] == ' ' || cmd[i] == '\t')) ++i;
        if (i >= n) break;
        std::string a;
        bool inq = false;
        while (i < n) {
            char c = cmd[i];
            if (!inq && (c == ' ' || c == '\t')) break;
            if (c == '\\') {
                size_t bs = 0;
                while (i < n && cmd[i] == '\\') { ++bs; ++i; }
                if (i < n && cmd[i] == '"') {
                    a.append(bs / 2, '\\');
                    if (bs % 2) { a += '"'; ++i; }
                } else {
                    a.append(bs, '\\');
                }
                continue;
            }
            if (c == '"') {
                // "" inside a quoted region yields a literal quote (post-2008 CRT rule).
                if (inq && i + 1 < n && cmd[i + 1] == '"') { a += '"'; i += 2; continue; }
                inq = !inq;
                ++i;
                continue;
            }
            a += c;
            ++i;
        }
        out.push_back(a);
    }
    return out;
}

namespace {

ProcessResult WaitFor(HANDLE process, const std::function<void()>& onCancel) {
    ProcessResult r;
    r.started = true;
    for (;;) {
        DWORD w = WaitForSingleObject(process, 250);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_FAILED) break;
        if (CancelRequested() && !r.cancelledWait) {
            r.cancelledWait = true;
            if (onCancel) onCancel();
        }
    }
    DWORD code = 0;
    GetExitCodeProcess(process, &code);
    r.exitCode = code;
    if (CancelRequested()) r.cancelledWait = true;
    return r;
}

ProcessResult RunElevated(const std::string& exe, const std::string& params, const std::string& workingDir,
                          const std::function<void()>& onCancel) {
    std::wstring wexe = Widen(exe), wparams = Widen(params), wdir = Widen(workingDir);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    sei.lpFile = wexe.c_str();
    sei.lpParameters = wparams.c_str();
    sei.lpDirectory = workingDir.empty() ? nullptr : wdir.c_str();
    sei.nShow = SW_SHOWNORMAL;
    ProcessResult r;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        r.startError = GetLastError();
        if (r.startError == 0) r.startError = ERROR_CANCELLED;
        return r;
    }
    r = WaitFor(sei.hProcess, onCancel);
    r.elevated = true;
    CloseHandle(sei.hProcess);
    return r;
}


std::string JoinArgs(const std::vector<std::string>& args) {
    std::string params;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) params += ' ';
        params += QuoteArgument(args[i]);
    }
    return params;
}

}  // namespace

std::string MsiPropertyArg(const std::string& name, const std::string& value) {
    std::string out = name + "=\"";
    for (char c : value) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

ProcessResult RunProcess(const std::string& exe, const std::vector<std::string>& args, Elevation elevation,
                         const std::string& workingDir, const std::function<void()>& onCancelNotice) {
    return RunProcessRaw(exe, JoinArgs(args), elevation, workingDir, onCancelNotice);
}

ProcessResult RunProcessRaw(const std::string& exe, const std::string& params, Elevation elevation,
                            const std::string& workingDir, const std::function<void()>& onCancelNotice) {
    if (elevation == Elevation::Always && !IsProcessElevated())
        return RunElevated(exe, params, workingDir, onCancelNotice);

    std::wstring wexe = Widen(exe);
    std::wstring cmd = Widen("\"" + exe + "\"" + (params.empty() ? "" : " " + params));
    std::wstring wdir = Widen(workingDir);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    // Explicit lpApplicationName: no PATH search, no ambiguity with spaces.
    BOOL ok = CreateProcessW(wexe.c_str(), &cmd[0], nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr,
                             workingDir.empty() ? nullptr : wdir.c_str(), &si, &pi);
    if (!ok) {
        ProcessResult r;
        r.startError = GetLastError();
        if (r.startError == ERROR_ELEVATION_REQUIRED && elevation == Elevation::IfRequired)
            return RunElevated(exe, params, workingDir, onCancelNotice);
        return r;
    }
    CloseHandle(pi.hThread);
    ProcessResult r = WaitFor(pi.hProcess, onCancelNotice);
    CloseHandle(pi.hProcess);
    return r;
}

}  // namespace sg
