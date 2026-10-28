#include "cli/args.h"

namespace sg {

ParsedArgs ParseArgs(const std::vector<std::string>& argv, ParseError& err) {
    ParsedArgs a;
    bool endOfOptions = false;
    auto fail = [&](const std::string& m) {
        if (!err.failed) {
            err.failed = true;
            err.message = m;
        }
    };
    for (size_t i = 0; i < argv.size(); ++i) {
        std::string tok = argv[i];
        if (!endOfOptions && tok == "--") {
            endOfOptions = true;
            continue;
        }
        bool isOption = !endOfOptions && tok.size() > 1 && tok[0] == '-' && tok != "-";
        if (!isOption) {
            if (a.command.empty()) a.command = tok;
            else a.positional.push_back(tok);
            continue;
        }
        std::string name = tok, inlineValue;
        bool hasInline = false;
        size_t eq = tok.find('=');
        if (tok.compare(0, 2, "--") == 0 && eq != std::string::npos) {
            name = tok.substr(0, eq);
            inlineValue = tok.substr(eq + 1);
            hasInline = true;
        }
        auto value = [&](std::string& dst) {
            if (hasInline) {
                dst = inlineValue;
            } else if (i + 1 < argv.size()) {
                dst = argv[++i];
            } else {
                fail("option " + name + " requires a value");
                return;
            }
            if (dst.empty()) fail("option " + name + " requires a non-empty value");
        };
        auto flag = [&](bool& dst) {
            if (hasInline) fail("option " + name + " does not take a value");
            dst = true;
        };
        if (name == "--help" || name == "-h" || name == "/?") flag(a.help);
        else if (name == "--yes" || name == "-y") flag(a.yes);
        else if (name == "--quiet" || name == "-q") flag(a.quiet);
        else if (name == "--verbose") flag(a.verbose);
        else if (name == "--json") flag(a.json);
        else if (name == "--dry-run") flag(a.dryRun);
        else if (name == "--no-color") flag(a.noColor);
        else if (name == "--user") flag(a.user);
        else if (name == "--machine") flag(a.machine);
        else if (name == "--all") flag(a.all);
        else if (name == "--force") flag(a.force);
        else if (name == "--replace") flag(a.replace);
        else if (name == "--repair") flag(a.repair);
        else if (name == "--arch") value(a.arch);
        else if (name == "--output" || name == "-o") value(a.output);
        else if (name == "--key-file") value(a.keyFile);
        else if (name == "--fingerprint") value(a.fingerprint);
        else if (name == "--name") value(a.name);
        else if (name == "--version") {
            // "sevenget --version" prints the program version; after a command
            // it selects a package version.
            if (a.command.empty() && !hasInline) a.showVersion = true;
            else value(a.version);
        } else {
            fail("unknown option '" + tok + "' (see 'sevenget help')");
        }
    }
    if (a.user && a.machine) fail("--user and --machine cannot be combined");
    if (a.quiet && a.verbose) fail("--quiet and --verbose cannot be combined");
    return a;
}

}  // namespace sg
