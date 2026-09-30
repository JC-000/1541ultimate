# Patches to the mbedTLS sources that ESP-IDF builds (esp-pqc's fork of 4.1.1 here), included after project().
# The fetched component stays as it is (the component manager checks its hash): each patched file is copied into
# the build directory, patched there, and compiled in place of the original.
#
# patches/mbedtls-tls13-hrr-cookie.patch: accept a cookie in a HelloRetryRequest and echo it (RFC 8446 4.2.2,
# Mbed-TLS/mbedtls#9543). Without it, a server that sends one (OpenJDK's JSSE always does) fails every handshake
# that needs a HelloRetryRequest, and with X25519MLKEM768 offered first that is every classical-only server.

find_program(MBEDTLS_PATCH_TOOL patch REQUIRED)
set(_file ssl_tls13_generic.c)
set(_patch "${CMAKE_CURRENT_LIST_DIR}/patches/mbedtls-tls13-hrr-cookie.patch")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_patch}")

get_target_property(_srcs mbedtls SOURCES)
get_target_property(_srcdir mbedtls SOURCE_DIR)
set(_orig "")
foreach(_s IN LISTS _srcs)
    if(_s MATCHES "(^|/)${_file}$")
        if(IS_ABSOLUTE "${_s}")
            set(_orig "${_s}")
        else()
            set(_orig "${_srcdir}/${_s}")
        endif()
        set(_entry "${_s}")
    endif()
endforeach()
if(NOT _orig)
    message(FATAL_ERROR "mbedtls_patches.cmake: ${_file} is not a source of the mbedtls target")
endif()
get_filename_component(_libdir "${_orig}" DIRECTORY)

set(_work "${CMAKE_BINARY_DIR}/mbedtls_patched")
file(REMOVE_RECURSE "${_work}")
file(MAKE_DIRECTORY "${_work}/library")
file(COPY_FILE "${_orig}" "${_work}/library/${_file}")
execute_process(COMMAND ${MBEDTLS_PATCH_TOOL} -p1 --forward --batch -i "${_patch}"
                WORKING_DIRECTORY "${_work}" RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "mbedtls_patches.cmake: ${_patch} does not apply to ${_orig}:\n${_out}")
endif()

list(REMOVE_ITEM _srcs "${_entry}")
list(APPEND _srcs "${_work}/library/${_file}")
set_property(TARGET mbedtls PROPERTY SOURCES ${_srcs})
# The copy is outside library/, so its #include "..." must still find the fork's private headers first, never
# IDF's stock ones (their handshake struct has no mlkem_sk)
set_source_files_properties("${_work}/library/${_file}" TARGET_DIRECTORY mbedtls
                            PROPERTIES COMPILE_OPTIONS "-iquote;${_libdir}")
message(STATUS "mbedTLS: ${_file} from ${_libdir} built with patches/mbedtls-tls13-hrr-cookie.patch")
