// SevenGet - append-only operation log (%LOCALAPPDATA%\SevenGet\logs\sevenget.log).
#pragma once

#include <string>

namespace sg {

class Log {
public:
    static void Init(const std::string& dir);
    static void Info(const std::string& msg);
    static void Warn(const std::string& msg);
    static void Error(const std::string& msg);
    static const std::string& Path();

private:
    static void Write(const char* level, const std::string& msg);
};

}  // namespace sg
