/*
 * ndebug_guard.h
 *
 * Included by every source file of main. esp-pqc's liboqs can leave CMAKE_BUILD_TYPE=Release in a build
 * directory, which defines NDEBUG for every file (see ../CMakeLists.txt). The configure-time check there
 * does not run when ninja rebuilds without re-running CMake, so any file of main that is compiled with
 * NDEBUG refuses to build.
 */

#ifndef NDEBUG_GUARD_H_
#define NDEBUG_GUARD_H_

#ifdef NDEBUG
#error "NDEBUG is defined: assert() and ESP_ERROR_CHECK() would be compiled out. Run: idf.py -DCMAKE_BUILD_TYPE=None reconfigure"
#endif

#endif /* NDEBUG_GUARD_H_ */
