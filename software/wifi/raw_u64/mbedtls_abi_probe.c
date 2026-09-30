/*
 * mbedtls_abi_probe.c
 *
 * Compiled inside the mbedtls library target (mbedtls_patches.cmake), so it sees the library's own include
 * order and compile definitions. tls_engine.c embeds these structures and compares their sizes with its own
 * at OPEN: esp-pqc's fork changes them with defines (MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 grows mbedtls_pk_context,
 * so every mbedtls_x509_crt), and a define that reaches the library but not main would corrupt memory.
 */
#include <stddef.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

// Order: mbedtls_pk_context, mbedtls_x509_crt, mbedtls_ssl_context, mbedtls_ssl_config (tls_engine.c)
const size_t bridge_mbedtls_abi_sizes[4] = { sizeof(mbedtls_pk_context), sizeof(mbedtls_x509_crt),
                                             sizeof(mbedtls_ssl_context), sizeof(mbedtls_ssl_config) };
