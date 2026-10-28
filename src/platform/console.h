// SevenGet - console output.
//
// Windows 7's conhost does not interpret ANSI escape sequences, so colors are
// applied with SetConsoleTextAttribute and only when the stream is a real
// console. Text goes through WriteConsoleW on consoles (correct Unicode in any
// code page) and as UTF-8 bytes when redirected to a file or pipe.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sg {

enum class Color { Default, Gray, Red, Green, Yellow, Cyan, White };

struct ConsoleOptions {
    bool color = true;     // already resolved against --no-color / config / redirection
    bool quiet = false;    // only errors and essential output
    bool verbose = false;  // debug messages to stderr
    bool json = false;     // stdout is reserved for the JSON document
};

class Console {
public:
    static void Init(const ConsoleOptions& o);
    static const ConsoleOptions& Options();

    static bool StdoutIsConsole();
    static bool StderrIsConsole();
    static bool StdinIsConsole();
    static int Width();  // columns of stdout console, or 100 when redirected

    // Primary output (stdout). Suppressed in JSON mode except WriteJson.
    static void Out(const std::string& s, Color c = Color::Default);
    static void OutLine(const std::string& s = {}, Color c = Color::Default);
    static void WriteJson(const std::string& s);  // always to stdout, newline appended

    // Status / progress messages (stderr), suppressed by --quiet and --json.
    static void Info(const std::string& s);
    // "Label... " then Status("OK") on the same line.
    static void Step(const std::string& label);
    static void StepResult(const std::string& result, Color c);
    static void Warn(const std::string& s);
    static void Error(const std::string& s);  // never suppressed
    static void Debug(const std::string& s);  // only with --verbose

    // In-place progress line on stderr (only when stderr is a console).
    static void Progress(const std::string& line);
    static void EndProgress();

    // Asks a yes/no question on the console. Returns false on EOF.
    static bool Confirm(const std::string& question);
    // Reads a line from stdin (console or redirected).
    static bool ReadLine(std::string& out);
};

// Simple aligned text table.
class Table {
public:
    explicit Table(std::vector<std::string> headers) : headers_(std::move(headers)) {}
    void AddRow(std::vector<std::string> row, Color c = Color::Default) {
        rows_.push_back(std::move(row));
        colors_.push_back(c);
    }
    bool Empty() const { return rows_.empty(); }
    void Print() const;

private:
    std::vector<std::string> headers_;
    std::vector<std::vector<std::string>> rows_;
    std::vector<Color> colors_;
};

}  // namespace sg
