set(EXTERNAL "../../../io/uart")

# The certificate bundle trusts Mozilla's roots and nothing kept by hand. With
# CROSS_SIGNED_VERIFY a chain a server sends through an old root that cross-signed a current
# one ends at the current root; without it ESP-IDF 6 appends cacrt_local.pem and checks only
# the issuer of the topmost certificate sent, which fails most recorded hosts. So the build
# refuses =n, and refuses a custom bundle directory that holds cross-sign anchors
# (anchors.pem, as esp-tls/ca-store keeps them for ESP-IDF 5.3).
if(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
    if(NOT CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
        message(FATAL_ERROR "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY must be y")
    endif()
    if(CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE)
        idf_build_get_property(project_dir PROJECT_DIR)
        get_filename_component(bundle_path ${CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH}
                               ABSOLUTE BASE_DIR "${project_dir}")
        if(EXISTS "${bundle_path}/anchors.pem" OR bundle_path MATCHES "anchors")
            message(FATAL_ERROR "the certificate bundle takes no cross-sign anchors "
                                "(${bundle_path}); CROSS_SIGNED_VERIFY replaces them")
        endif()
    endif()
endif()
# BRIDGE_TLS_STUB (idf.py -D BRIDGE_TLS_STUB=1) builds a size-measurement image without the TLS engine
if(BRIDGE_TLS_STUB)
    set(TLS_SRCS "tls_engine_stub.c")
    set(TLS_EMBED "")
else()
    set(TLS_SRCS "tls_engine.c")
    set(TLS_EMBED EMBED_TXTFILES "tls_test_ca.pem")
endif()
idf_component_register(SRCS "main.c" "my_uart.c" "rpc_dispatch.c" "dump_hex.c" "wifi_modem.c" "sntp.c" ${TLS_SRCS} ${EXTERNAL}/cmd_buffer.c
                    INCLUDE_DIRS "." ${EXTERNAL}
                    ${TLS_EMBED})
