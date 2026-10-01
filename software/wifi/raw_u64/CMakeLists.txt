# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bridge)

# The certificate bundle is the vendored Mozilla root store, ../ca_store/cacert.pem (sdkconfig: DEFAULT_NONE plus
# CUSTOM_CERTIFICATE_BUNDLE_PATH). ca_store.py checks it against ../ca_store/CA_PINS, and the configuration this build
# really uses (its sdkconfig.json) against the store's rules: at every configure (an edit to the store, its pins or
# the checker configures again), and again at every build, before the bundle is made, so a tree configured earlier
# cannot skip it. RELEASE=1 in the environment also fails a stale store. How the store is refreshed: README.md.
set(CA_STORE ${CMAKE_CURRENT_LIST_DIR}/../ca_store)
set(CA_STORE_CHECK ${CMAKE_CURRENT_LIST_DIR}/../../../tools/ca_store/ca_store.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CA_STORE}/cacert.pem ${CA_STORE}/CA_PINS ${CA_STORE_CHECK})
idf_build_get_property(_python PYTHON)
idf_build_get_property(_sdkconfig_json SDKCONFIG_JSON)
set(_ca_check ${_python} ${CA_STORE_CHECK} check --project ${CMAKE_CURRENT_LIST_DIR} --sdkconfig-json ${_sdkconfig_json})
execute_process(COMMAND ${_ca_check} RESULT_VARIABLE _ca_rc)
if(NOT _ca_rc EQUAL 0)
    message(FATAL_ERROR "The Mozilla root store (software/wifi/ca_store) failed its check; see README.md")
endif()
add_custom_target(ca_store_check ALL COMMAND ${_ca_check} COMMENT "Checking the Mozilla root store" VERBATIM)
# The bundle (and so the mbedtls library and the image) waits for it
if(TARGET custom_bundle)
    add_dependencies(custom_bundle ca_store_check)
endif()
