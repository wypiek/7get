// SevenGet - command dispatcher.
#pragma once

#include <string>
#include <vector>

namespace sg {

extern const char kSevenGetVersion[];

// Runs the CLI with already-decoded UTF-8 arguments (argv[0] excluded) and
// returns the process exit code.
int RunCli(const std::vector<std::string>& args);

}  // namespace sg
