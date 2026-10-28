#include "platform/console.h"

#include <windows.h>

#include <algorithm>

#include "util/strings.h"

namespace sg {

namespace {

ConsoleOptions g_opts;
bool g_progressActive = false;
size_t g_progressWidth = 0;
bool g_stepOpen = false;

bool IsConsoleHandle(HANDLE h) {
    DWORD mode;
    return h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode);
}

WORD AttrFor(Color c, WORD def) {
    switch (c) {
        case Color::Gray: return FOREGROUND_INTENSITY;
        case Color::Red: return FOREGROUND_RED | FOREGROUND_INTENSITY;
        case Color::Green: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Yellow: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Cyan: return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case Color::White: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        default: return def;
    }
}

void WriteRaw(DWORD which, const std::string& s, Color c = Color::Default) {
    HANDLE h = GetStdHandle(which);
    if (!h || h == INVALID_HANDLE_VALUE || s.empty()) return;
    if (IsConsoleHandle(h)) {
        CONSOLE_SCREEN_BUFFER_INFO info{};
        bool colored = g_opts.color && c != Color::Default && GetConsoleScreenBufferInfo(h, &info);
        WORD saved = info.wAttributes;
        if (colored) SetConsoleTextAttribute(h, static_cast<WORD>((saved & 0xF0) | AttrFor(c, saved)));
        std::wstring w = Widen(s);
        size_t off = 0;
        while (off < w.size()) {
            DWORD chunk = static_cast<DWORD>(std::min<size_t>(w.size() - off, 8192));
            DWORD written = 0;
            if (!WriteConsoleW(h, w.data() + off, chunk, &written, nullptr) || written == 0) break;
            off += written;
        }
        if (colored) SetConsoleTextAttribute(h, saved);
    } else {
        // Redirected: UTF-8 bytes, LF -> CRLF for Notepad-friendly files.
        std::string data;
        data.reserve(s.size() + 16);
        for (char ch : s) {
            if (ch == '\n') data += '\r';
            data += ch;
        }
        DWORD written = 0;
        WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    }
}

void ClearProgress() {
    if (!g_progressActive) return;
    WriteRaw(STD_ERROR_HANDLE, "\r" + std::string(g_progressWidth, ' ') + "\r");
    g_progressActive = false;
}

void CloseStep() {
    if (g_stepOpen) {
        WriteRaw(STD_ERROR_HANDLE, "\n");
        g_stepOpen = false;
    }
}

}  // namespace

void Console::Init(const ConsoleOptions& o) {
    g_opts = o;
    // Colors only make sense on a real console.
    if (!StdoutIsConsole() && !StderrIsConsole()) g_opts.color = false;
}

const ConsoleOptions& Console::Options() { return g_opts; }

bool Console::StdoutIsConsole() { return IsConsoleHandle(GetStdHandle(STD_OUTPUT_HANDLE)); }
bool Console::StderrIsConsole() { return IsConsoleHandle(GetStdHandle(STD_ERROR_HANDLE)); }
bool Console::StdinIsConsole() { return IsConsoleHandle(GetStdHandle(STD_INPUT_HANDLE)); }

int Console::Width() {
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (IsConsoleHandle(h) && GetConsoleScreenBufferInfo(h, &info))
        return info.srWindow.Right - info.srWindow.Left + 1;
    return 100;
}

void Console::Out(const std::string& s, Color c) {
    if (g_opts.json) return;
    ClearProgress();
    CloseStep();
    WriteRaw(STD_OUTPUT_HANDLE, s, c);
}

void Console::OutLine(const std::string& s, Color c) {
    if (g_opts.json) return;
    Out(s, c);
    WriteRaw(STD_OUTPUT_HANDLE, "\n");
}

void Console::WriteJson(const std::string& s) {
    ClearProgress();
    WriteRaw(STD_OUTPUT_HANDLE, s + "\n");
}

void Console::Info(const std::string& s) {
    if (g_opts.quiet || g_opts.json) return;
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, s + "\n");
}

void Console::Step(const std::string& label) {
    if (g_opts.quiet || g_opts.json) return;
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, label + "... ");
    g_stepOpen = true;
}

void Console::StepResult(const std::string& result, Color c) {
    if (g_opts.quiet || g_opts.json) return;
    ClearProgress();
    WriteRaw(STD_ERROR_HANDLE, result, c);
    WriteRaw(STD_ERROR_HANDLE, "\n");
    g_stepOpen = false;
}

void Console::Warn(const std::string& s) {
    if (g_opts.json) return;
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, "Warning: ", Color::Yellow);
    WriteRaw(STD_ERROR_HANDLE, s + "\n");
}

void Console::Error(const std::string& s) {
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, "Error: ", Color::Red);
    WriteRaw(STD_ERROR_HANDLE, s + "\n");
}

void Console::Debug(const std::string& s) {
    if (!g_opts.verbose) return;
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, "[debug] " + s + "\n", Color::Gray);
}

void Console::Progress(const std::string& line) {
    if (g_opts.quiet || g_opts.json || !StderrIsConsole()) return;
    CloseStep();
    // Keep within the console width to avoid wrapping (which breaks \r).
    std::string l = line;
    CONSOLE_SCREEN_BUFFER_INFO info;
    size_t width = 79;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &info))
        width = static_cast<size_t>(std::max(20, info.srWindow.Right - info.srWindow.Left));
    if (l.size() > width) l.resize(width);
    size_t pad = g_progressWidth > l.size() ? g_progressWidth - l.size() : 0;
    WriteRaw(STD_ERROR_HANDLE, "\r" + l + std::string(pad, ' '));
    g_progressWidth = l.size();
    g_progressActive = true;
}

void Console::EndProgress() {
    if (!g_progressActive) return;
    WriteRaw(STD_ERROR_HANDLE, "\n");
    g_progressActive = false;
    g_progressWidth = 0;
}

bool Console::ReadLine(std::string& out) {
    out.clear();
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    if (IsConsoleHandle(h)) {
        wchar_t buf[512];
        DWORD read = 0;
        if (!ReadConsoleW(h, buf, 511, &read, nullptr)) return false;
        if (read == 0) return false;
        std::wstring w(buf, read);
        out = Trim(Narrow(w));
        return true;
    }
    // Redirected stdin: read bytes until newline.
    char c;
    DWORD got = 0;
    bool any = false;
    while (ReadFile(h, &c, 1, &got, nullptr) && got == 1) {
        any = true;
        if (c == '\n') break;
        out += c;
    }
    out = Trim(out);
    return any;
}

bool Console::Confirm(const std::string& question) {
    ClearProgress();
    CloseStep();
    WriteRaw(STD_ERROR_HANDLE, question + " [y/N] ", Color::White);
    std::string answer;
    if (!ReadLine(answer)) {
        WriteRaw(STD_ERROR_HANDLE, "\n");
        return false;
    }
    answer = ToLowerAscii(answer);
    return answer == "y" || answer == "yes";
}

void Table::Print() const {
    std::vector<size_t> widths(headers_.size(), 0);
    for (size_t i = 0; i < headers_.size(); ++i) widths[i] = DisplayWidth(headers_[i]);
    for (const auto& r : rows_)
        for (size_t i = 0; i < r.size() && i < widths.size(); ++i) widths[i] = std::max(widths[i], DisplayWidth(r[i]));
    // Shrink the widest column if the table would wrap on the console.
    size_t total = 0;
    for (size_t w : widths) total += w + 2;
    size_t avail = static_cast<size_t>(std::max(40, Console::Width() - 1));
    if (Console::StdoutIsConsole() && total > avail && !widths.empty()) {
        size_t widest = static_cast<size_t>(std::max_element(widths.begin(), widths.end()) - widths.begin());
        size_t excess = total - avail;
        widths[widest] = widths[widest] > excess + 8 ? widths[widest] - excess : 8;
    }
    auto cell = [&](const std::string& s, size_t w, bool last) {
        std::string out = s;
        size_t dw = DisplayWidth(out);
        if (dw > w) {
            // Truncate on a UTF-8 boundary and mark with "~".
            std::wstring ws = Widen(out);
            while (!ws.empty() && DisplayWidth(Narrow(ws)) > (w > 1 ? w - 1 : 0)) ws.pop_back();
            out = Narrow(ws) + "~";
            dw = DisplayWidth(out);
        }
        if (!last) out += std::string(w - std::min(w, dw) + 2, ' ');
        return out;
    };
    std::string line;
    for (size_t i = 0; i < headers_.size(); ++i) line += cell(headers_[i], widths[i], i + 1 == headers_.size());
    Console::OutLine(line, Color::Cyan);
    for (size_t r = 0; r < rows_.size(); ++r) {
        line.clear();
        for (size_t i = 0; i < headers_.size(); ++i)
            line += cell(i < rows_[r].size() ? rows_[r][i] : "", widths[i], i + 1 == headers_.size());
        Console::OutLine(line, colors_[r]);
    }
}

}  // namespace sg
