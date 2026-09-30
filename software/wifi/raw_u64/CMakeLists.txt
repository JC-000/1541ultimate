# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

# ESP-IDF sets no CMAKE_BUILD_TYPE. esp-pqc builds liboqs with add_subdirectory(), and liboqs then forces
# CMAKE_BUILD_TYPE=Release into the cache, which puts -O3 -DNDEBUG on every file of the firmware and
# compiles out assert() and ESP_ERROR_CHECK(). "None" adds no flags and keeps liboqs from choosing.
# FORCE, because a build directory configured before esp-pqc already caches an empty value.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE None CACHE STRING "No per-config flags: ESP-IDF sets its own" FORCE)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bridge)

# A build directory that liboqs already set to Release keeps it: refuse it rather than build without asserts
if(NOT CMAKE_BUILD_TYPE STREQUAL "None")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE is '${CMAKE_BUILD_TYPE}', which adds -O3 -DNDEBUG to every file. "
                        "Run 'idf.py fullclean' (or configure with -DCMAKE_BUILD_TYPE=None).")
endif()
