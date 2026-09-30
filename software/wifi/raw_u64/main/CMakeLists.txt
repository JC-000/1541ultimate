set(EXTERNAL "../../../io/uart")
# The bridge offers X25519MLKEM768 first (M4). Without esp-pqc (IDF_COMPONENT_MANAGER=0, or the dependency not
# resolved) the option does not exist, and the image would silently be classical-only under the same IDENT.
# Not in IDF's early requirements pass, which runs this file before esp-pqc's Kconfig options are known.
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND NOT CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)
    message(FATAL_ERROR "X25519MLKEM768 is off, or esp-pqc (main/idf_component.yml) is missing: the bridge "
                        "offers it first. Build with the component manager on and restore the committed sdkconfig")
endif()
# esp-pqc builds its mbedTLS fork but leaves IDF's stock mbedTLS headers first on the include path. Code that
# includes the stock library/ssl_misc.h then sees a handshake struct without the fork's 2,400-byte mlkem_sk
# and reads members after it at the wrong offset. These two options compile such code in.
if(CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768 AND
   (CONFIG_MBEDTLS_DYNAMIC_BUFFER OR CONFIG_ESP_WIFI_MBEDTLS_TLS_CLIENT))
    message(FATAL_ERROR "X25519MLKEM768 (esp-pqc) cannot be combined with MBEDTLS_DYNAMIC_BUFFER or "
                        "ESP_WIFI_MBEDTLS_TLS_CLIENT: they include IDF's stock ssl_misc.h")
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
