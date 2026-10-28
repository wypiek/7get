cmake_minimum_required(VERSION 3.16)

project(SevenGet VERSION 1.0.0 LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
  message(FATAL_ERROR "SevenGet targets Windows. Use a Windows toolchain or cmake/mingw-x64.cmake / cmake/mingw-x86.cmake.")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SEVENGET_BUILD_TESTS "Build unit tests" ON)

# Executables land directly in the build directory, e.g. build/x64/sevenget.exe.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
foreach(cfg Debug Release RelWithDebInfo MinSizeRel)
  string(TOUPPER ${cfg} CFG)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CFG} ${CMAKE_BINARY_DIR})
endforeach()

# Windows 7 SP1 is the minimum target: headers expose only NT 6.1 APIs.
set(SEVENGET_DEFINES
  _WIN32_WINNT=0x0601 WINVER=0x0601 NTDDI_VERSION=0x06010000
  UNICODE _UNICODE NOMINMAX _CRT_SECURE_NO_WARNINGS)

if(MSVC)
  # Static CRT: no Visual C++ Redistributable needed on the target.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  set(SEVENGET_CXX_FLAGS /W4 /utf-8 /permissive- /EHsc /wd4100)
  set(SEVENGET_LINK_FLAGS /SUBSYSTEM:CONSOLE,6.01 /MANIFEST:NO /DYNAMICBASE /NXCOMPAT)
  set(SEVENGET_C_FLAGS /utf-8 /W2)
else()
  set(SEVENGET_CXX_FLAGS -Wall -Wextra -Wno-unused-parameter -Wno-cast-function-type)
  set(SEVENGET_C_FLAGS -Wno-unused -Wno-implicit-fallthrough)
  set(SEVENGET_LINK_FLAGS
    -municode -static -static-libgcc -static-libstdc++
    -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,1
    -Wl,--major-os-version,6 -Wl,--minor-os-version,1
    -Wl,--dynamicbase -Wl,--nxcompat)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND SEVENGET_LINK_FLAGS -Wl,--high-entropy-va)
  endif()
  if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    list(APPEND SEVENGET_LINK_FLAGS -s)
  endif()
endif()

# --- third party -----------------------------------------------------------
add_library(sqlite3 STATIC third_party/sqlite/sqlite3.c)
target_include_directories(sqlite3 PUBLIC third_party/sqlite)
target_compile_definitions(sqlite3 PRIVATE ${SEVENGET_DEFINES}
  SQLITE_THREADSAFE=1 SQLITE_DEFAULT_FOREIGN_KEYS=1 SQLITE_DQS=0
  SQLITE_OMIT_LOAD_EXTENSION SQLITE_OMIT_DEPRECATED SQLITE_DEFAULT_WAL_SYNCHRONOUS=2
  SQLITE_WIN32_NO_ANSI=0)
target_compile_options(sqlite3 PRIVATE ${SEVENGET_C_FLAGS})

add_library(miniz STATIC third_party/miniz/miniz.c)
target_include_directories(miniz PUBLIC third_party/miniz)
target_compile_definitions(miniz PRIVATE ${SEVENGET_DEFINES} MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ZLIB_COMPATIBLE_NAMES)
target_compile_definitions(miniz PUBLIC MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ZLIB_COMPATIBLE_NAMES)
target_compile_options(miniz PRIVATE ${SEVENGET_C_FLAGS})

# --- core library ------------------------------------------------------------
add_library(sevenget_core STATIC
  src/util/strings.cpp
  src/util/json.cpp
  src/util/version.cpp
  src/util/log.cpp
  src/platform/winutil.cpp
  src/platform/process.cpp
  src/platform/console.cpp
  src/platform/crypto.cpp
  src/platform/authenticode.cpp
  src/platform/http.cpp
  src/core/manifest.cpp
  src/core/resolver.cpp
  src/core/repository.cpp
  src/core/database.cpp
  src/core/config.cpp
  src/install/zip_extract.cpp
  src/install/backend.cpp
  src/install/exe_backend.cpp
  src/install/msi_backend.cpp
  src/install/zip_backend.cpp
  src/install/engine.cpp
  src/cli/args.cpp
  src/cli/commands.cpp
  src/cli/cmd_system.cpp
)
target_include_directories(sevenget_core PUBLIC src)
target_compile_definitions(sevenget_core PUBLIC ${SEVENGET_DEFINES})
target_compile_options(sevenget_core PRIVATE ${SEVENGET_CXX_FLAGS})
target_link_libraries(sevenget_core PUBLIC sqlite3 miniz
  winhttp bcrypt crypt32 wintrust msi shell32 advapi32 user32)

# --- executables -------------------------------------------------------------
add_executable(sevenget src/main.cpp res/sevenget.rc)
target_link_libraries(sevenget PRIVATE sevenget_core)
target_compile_options(sevenget PRIVATE ${SEVENGET_CXX_FLAGS})
target_link_options(sevenget PRIVATE ${SEVENGET_LINK_FLAGS})

add_executable(sevenget-repotool tools/repotool/repotool.cpp)
target_link_libraries(sevenget-repotool PRIVATE sevenget_core)
target_compile_options(sevenget-repotool PRIVATE ${SEVENGET_CXX_FLAGS})
target_link_options(sevenget-repotool PRIVATE ${SEVENGET_LINK_FLAGS})

if(SEVENGET_BUILD_TESTS)
  enable_testing()
  add_executable(sevenget_tests
    tests/test_main.cpp
    tests/test_json.cpp
    tests/test_version.cpp
    tests/test_manifest.cpp
    tests/test_resolver.cpp
    tests/test_security.cpp
    tests/test_process.cpp
    tests/test_database.cpp
    tests/test_zip.cpp
    tests/test_cli.cpp
  )
  target_link_libraries(sevenget_tests PRIVATE sevenget_core)
  target_compile_options(sevenget_tests PRIVATE ${SEVENGET_CXX_FLAGS})
  target_link_options(sevenget_tests PRIVATE ${SEVENGET_LINK_FLAGS})
  target_compile_definitions(sevenget_tests PRIVATE SEVENGET_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
  add_test(NAME unit COMMAND sevenget_tests)
endif()

install(TARGETS sevenget sevenget-repotool RUNTIME DESTINATION .)
install(FILES README.md LICENSE THIRD_PARTY_NOTICES.md DESTINATION .)
