// SevenGet - command-line argument parser.
#pragma once

#include <string>
#include <vector>

namespace sg {

struct ParsedArgs {
    std::string command;               // "install", "repo", ...
    std::vector<std::string> positional;  // arguments after the command
    // Global flags
    bool help = false;
    bool showVersion = false;          // --version without a value / before the command
    bool yes = false, quiet = false, verbose = false, json = false, dryRun = false, noColor = false;
    bool user = false, machine = false, all = false, force = false, replace = false, repair = false;
    std::string arch;                  // --arch
    std::string version;               // --version <v> (selection)
    std::string output;                // --output <dir>
    std::string keyFile;               // --key-file <path>
    std::string fingerprint;           // --fingerprint <hex>
    std::string name;                  // --name <repo-name>
};

struct ParseError {
    bool failed = false;
    std::string message;
};

// argv excludes the program name. Supports "--flag value" and "--flag=value",
// "--" terminates option parsing.
ParsedArgs ParseArgs(const std::vector<std::string>& argv, ParseError& err);

}  // namespace sg
