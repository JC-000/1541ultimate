# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bridge)

# The certificate bundle is the vendored Mozilla root store, ../ca_store/cacert.pem (sdkconfig: DEFAULT_NONE plus
# CUSTOM_CERTIFICATE_BUNDLE_PATH). Every configure checks it against ../ca_store/CA_PINS, and an edit to either
# configures again, so a store that does not match its pins fails the build. RELEASE=1 also fails a stale store.
# How the store is refreshed and checked: README.md.
set(CA_STORE ${CMAKE_CURRENT_LIST_DIR}/../ca_store)
set(CA_STORE_CHECK ${CMAKE_CURRENT_LIST_DIR}/../../../tools/ca_store/ca_store.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CA_STORE}/cacert.pem ${CA_STORE}/CA_PINS ${CA_STORE_CHECK})
set(_ca_release "")
if(DEFINED ENV{RELEASE} AND NOT "$ENV{RELEASE}" STREQUAL "0")
    set(_ca_release "--release")
endif()
idf_build_get_property(_python PYTHON)
execute_process(COMMAND ${_python} ${CA_STORE_CHECK} check ${_ca_release} RESULT_VARIABLE _ca_rc)
if(NOT _ca_rc EQUAL 0)
    message(FATAL_ERROR "The Mozilla root store (software/wifi/ca_store) failed its check; see README.md")
endif()
