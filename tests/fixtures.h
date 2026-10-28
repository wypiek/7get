// Shared test fixtures.
#pragma once

#include <string>

#include "util/json.h"

namespace sgtest {

// A valid manifest with two releases:
//   2.0 -> x64 exe requiring Windows NT 10.0 (not Windows 7 compatible)
//   1.5 -> x64 msi + x86 exe (NT 6.1+), x64 zip (user scope)
inline std::string SampleManifestText(const std::string& id = "Example.Tool") {
    return R"({
  "id": ")" + id + R"(",
  "name": "Example Tool",
  "publisher": "Example Corp",
  "description": "A test package",
  "license": "MIT",
  "homepage": "https://example.invalid/",
  "tags": ["test", "tool"],
  "releases": [
    {
      "version": "2.0",
      "installers": [
        {"arch": "x64", "type": "exe", "url": "https://example.invalid/tool-2.0-x64.exe",
         "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
         "minWindows": "10.0", "scope": ["machine"], "silentArgs": ["/S"],
         "uninstall": {"strategy": "registry", "registryKey": "ExampleTool", "quietArgs": ["/S"]}}
      ]
    },
    {
      "version": "1.5",
      "installers": [
        {"arch": "x64", "type": "msi", "url": "https://example.invalid/tool-1.5-x64.msi",
         "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
         "minWindows": "6.1", "scope": ["machine"], "uninstall": {"strategy": "msi"}},
        {"arch": "x86", "type": "exe", "url": "https://example.invalid/tool-1.5.exe",
         "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
         "minWindows": "6.1", "scope": ["machine"], "silentArgs": ["/S", "/NORESTART"],
         "uninstall": {"strategy": "registry", "registryKey": "ExampleTool"}},
        {"arch": "x64", "type": "zip", "url": "https://example.invalid/tool-1.5-x64.zip",
         "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
         "minWindows": "6.1", "scope": ["user", "machine"], "uninstall": {"strategy": "files"},
         "signature": {"required": true, "subject": "Example Corp", "files": ["tool.exe"]}}
      ]
    }
  ]
})";
}

}  // namespace sgtest
