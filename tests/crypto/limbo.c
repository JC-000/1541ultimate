/*
 * x509-limbo harness for mbedTLS: validates a server's chain the way the TLS 1.3 client does in
 * ssl_tls13_validate_certificate() (library/ssl_tls13_generic.c): the chain from the
 * Certificate message against the configured CA chain, with the default certificate profile and
 * the host name, and then the leaf's keyUsage (digitalSignature) and extendedKeyUsage
 * (serverAuth). tls_engine.c configures no CRL and no verify callback when it verifies.
 *
 * One test case per line on stdin, certificates as DER in hex:
 *   <validation time, unix> <host name> <leaf> <n> <intermediate>... <m> <trusted>...
 * One result per line on stdout: "<ret> <verify flags in hex>", ret 0 when the chain is accepted.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"

// mbedTLS reads the clock through time() (MBEDTLS_HAVE_TIME_DATE, mbedtls_time() is time());
// this definition in the executable answers with the test case's validation time.
static time_t validation_time;

time_t time(time_t *t)
{
    if (t) {
        *t = validation_time;
    }
    return validation_time;
}

static unsigned char *unhex(const char *s, size_t *len)
{
    *len = strlen(s) / 2;
    unsigned char *p = malloc(*len + 1);
    for (size_t i = 0; i < *len; i++) {
        unsigned int v;
        sscanf(s + 2 * i, "%2x", &v);
        p[i] = (unsigned char)v;
    }
    return p;
}

// Parses certificates the way each side gets them: the peer's as ssl_tls13_parse_certificate()
// takes the Certificate message's entries (one that does not parse fails the handshake, except
// for an unknown signature algorithm, which is skipped), the trusted ones as tls_engine.c
// does (any certificate that does not parse fails the OPEN)
static int parse(mbedtls_x509_crt *chain, char *hex, int peer)
{
    size_t len;
    unsigned char *der = unhex(hex, &len);
    int ret = mbedtls_x509_crt_parse_der(chain, der, len);
    free(der);
    if (peer && (ret == MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND)) {
        ret = 0;
    }
    return ret;
}

static void run_line(char *line)
{
    char *save;
    char *when = strtok_r(line, " \n", &save);
    char *host = strtok_r(NULL, " \n", &save);
    char *leaf = strtok_r(NULL, " \n", &save);
    mbedtls_x509_crt chain, trusted;
    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&trusted);
    validation_time = (time_t)strtoll(when, NULL, 10);

    int ret = parse(&chain, leaf, 1);
    int n = atoi(strtok_r(NULL, " \n", &save));
    for (int i = 0; i < n; i++) {
        char *hex = strtok_r(NULL, " \n", &save);
        ret = ret ? ret : parse(&chain, hex, 1);
    }
    n = atoi(strtok_r(NULL, " \n", &save));
    for (int i = 0; i < n; i++) {
        char *hex = strtok_r(NULL, " \n", &save);
        ret = ret ? ret : parse(&trusted, hex, 0);
    }
    uint32_t flags = 0;
    if ((ret == 0) && (chain.raw.p == NULL)) {
        ret = -2; // every entry skipped: the client has no peer certificate and aborts
    } else if (ret == 0) {
        ret = mbedtls_x509_crt_verify_with_profile(&chain, &trusted, NULL, &mbedtls_x509_crt_profile_default,
                                                   host, &flags, NULL, NULL);
        if ((mbedtls_x509_crt_check_key_usage(&chain, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0) ||
            (mbedtls_x509_crt_check_extended_key_usage(&chain, MBEDTLS_OID_SERVER_AUTH,
                                                       MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0)) {
            ret = ret ? ret : -1; // MBEDTLS_ERR_SSL_BAD_CERTIFICATE in the TLS layer
        }
    }
    printf("%d %08x\n", ret, (unsigned)flags);
    fflush(stdout);
    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_free(&trusted);
}

int main(void)
{
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        run_line(line);
    }
    free(line);
    return 0;
}
