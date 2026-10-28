#include "install/backend.h"

#include <cstdio>

#include "platform/winutil.h"
#include "util/strings.h"

namespace sg {

std::unique_ptr<InstallerBackend> CreateExeBackend();
std::unique_ptr<InstallerBackend> CreateMsiBackend();
std::unique_ptr<InstallerBackend> CreateZipBackend();

std::unique_ptr<InstallerBackend> CreateBackend(InstallerType t) {
    switch (t) {
        case InstallerType::Exe: return CreateExeBackend();
        case InstallerType::Msi: return CreateMsiBackend();
        case InstallerType::Zip: return CreateZipBackend();
    }
    return nullptr;
}

bool InstallerTypeFromName(const std::string& name, InstallerType& out) {
    if (name == "exe") out = InstallerType::Exe;
    else if (name == "msi") out = InstallerType::Msi;
    else if (name == "zip") out = InstallerType::Zip;
    else return false;
    return true;
}

BackendResult::Status ClassifyExitCode(uint32_t code, const std::vector<int64_t>& success,
                                       const std::vector<int64_t>& reboot) {
    for (auto c : success)
        if (static_cast<uint32_t>(c) == code) return BackendResult::Status::Success;
    for (auto c : reboot)
        if (static_cast<uint32_t>(c) == code) return BackendResult::Status::RebootRequired;
    switch (code) {
        case 1602:  // ERROR_INSTALL_USEREXIT
        case 1223:  // ERROR_CANCELLED
            return BackendResult::Status::Cancelled;
        case 1618:  // ERROR_INSTALL_ALREADY_RUNNING
            return BackendResult::Status::Busy;
        default:
            return BackendResult::Status::Failed;
    }
}

std::string DescribeInstallerExitCode(uint32_t code) {
    const char* text = nullptr;
    switch (code) {
        case 0: text = "success"; break;
        case 1223: text = "the operation was cancelled by the user"; break;
        case 1602: text = "the user cancelled the installation"; break;
        case 1603: text = "fatal error during installation"; break;
        case 1618: text = "another installation is already in progress"; break;
        case 1619: text = "the installation package could not be opened"; break;
        case 1620: text = "the installation package is invalid"; break;
        case 1625: text = "installation is forbidden by system policy"; break;
        case 1633: text = "this installation package is not supported on this processor type"; break;
        case 1638: text = "another version of this product is already installed"; break;
        case 1641: text = "installation succeeded and a restart was initiated"; break;
        case 3010: text = "installation succeeded; a restart is required"; break;
        default: break;
    }
    char buf[64];
    std::snprintf(buf, sizeof buf, "exit code %lu", static_cast<unsigned long>(code));
    return text ? std::string(buf) + " (" + text + ")" : std::string(buf);
}

bool IsForbiddenUninstallHost(const std::string& exePath) {
    std::string n = ToLowerAscii(FileName(exePath));
    static const char* hosts[] = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                                  "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe"};
    for (const char* h : hosts)
        if (n == h) return true;
    return false;
}

}  // namespace sg
