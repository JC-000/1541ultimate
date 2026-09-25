set(EXTERNAL "../../../io/uart")
idf_component_register(SRCS "main.c" "my_uart.c" "rpc_dispatch.c" "dump_hex.c" "wifi_modem.c" "sntp.c" ${EXTERNAL}/cmd_buffer.c
                    "tls_size_probe.c"
                    INCLUDE_DIRS "." ${EXTERNAL})

# M2 SPIKE: idf.py -D TLS_SIZE_PROBE=1 links the TLS size probe (tls_size_probe.c)
if(TLS_SIZE_PROBE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE TLS_SIZE_PROBE)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u tls_size_probe")
endif()
