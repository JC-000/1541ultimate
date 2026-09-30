# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# ESP-IDF sets no CMAKE_BUILD_TYPE. esp-pqc builds liboqs with add_subdirectory(), and liboqs then forces
# CMAKE_BUILD_TYPE=Release into the cache, which puts -O3 -DNDEBUG on every file of the firmware and
# compiles out assert() and ESP_ERROR_CHECK(). "None" adds no flags and keeps liboqs from choosing.
# FORCE, because a build directory configured before esp-pqc already caches an empty value.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE None CACHE STRING "No per-config flags: ESP-IDF sets its own" FORCE)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bridge)

# A build directory that liboqs already set to Release keeps it: refuse any build type whose flags define
# NDEBUG (Release, RelWithDebInfo, MinSizeRel) rather than build without asserts. Every source file of main also
# refuses NDEBUG at compile time (main/ndebug_guard.h), for a build that ninja runs without re-running this configure.
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
if(CMAKE_C_FLAGS_${BUILD_TYPE_UPPER} MATCHES "NDEBUG")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE is '${CMAKE_BUILD_TYPE}', which adds '${CMAKE_C_FLAGS_${BUILD_TYPE_UPPER}}' "
                        "to every file and compiles out assert() and ESP_ERROR_CHECK(). "
                        "Run: idf.py -DCMAKE_BUILD_TYPE=None reconfigure")
endif()
