# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

# ESP-IDF sets no CMAKE_BUILD_TYPE. esp-pqc builds liboqs with add_subdirectory(), and liboqs then forces
# CMAKE_BUILD_TYPE=Release into the cache, which puts -O3 -DNDEBUG on every file of the firmware and
# compiles out assert() and ESP_ERROR_CHECK(). "None" adds no flags and keeps liboqs from choosing.
set(CMAKE_BUILD_TYPE None CACHE STRING "No per-config flags: ESP-IDF sets its own")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bridge)
