/* M2 SPIKE: TLS size probe. Not for upstream.
 *
 * mbedTLS only links what something calls, so without a caller a TLS
 * configuration costs nothing in bridge.bin. This file references the calls a
 * TLS client needs, so that the image size of a given sdkconfig can be
 * measured. It is only compiled in with `idf.py -D TLS_SIZE_PROBE=1 build`,
 * which also passes `-u tls_size_probe` to the linker; nothing calls it.
 */
#ifdef TLS_SIZE_PROBE
#include <string.h>
#include "esp_random.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "psa/crypto.h"
#include "sdkconfig.h"
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif

static int probe_entropy(void *ctx, unsigned char *buf, size_t len)
{
    esp_fill_random(buf, len);
    return 0;
}

static int probe_send(void *ctx, const unsigned char *buf, size_t len)
{
    return (int)len;
}

static int probe_recv(void *ctx, unsigned char *buf, size_t len)
{
    return MBEDTLS_ERR_SSL_WANT_READ;
}

int tls_size_probe(const unsigned char *pem, size_t pem_len, const char *host)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_x509_crt ca;
    unsigned char buf[64];
    uint32_t flags;
    int ret;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_x509_crt_init(&ca);

    /* mbedTLS 3.6: TLS 1.3 needs PSA initialised before the handshake */
    ret = (int)psa_crypto_init();
    ret |= mbedtls_ctr_drbg_seed(&drbg, probe_entropy, NULL, NULL, 0);
    ret |= mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    ret |= mbedtls_x509_crt_parse(&ca, pem, pem_len);
    mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    ret |= esp_crt_bundle_attach(&conf);
#endif
    ret |= mbedtls_ssl_setup(&ssl, &conf);
    ret |= mbedtls_ssl_set_hostname(&ssl, host);
    mbedtls_ssl_set_bio(&ssl, NULL, probe_send, probe_recv, NULL);
    ret |= mbedtls_ssl_handshake(&ssl);
    ret |= mbedtls_x509_crt_verify(&ca, &ca, NULL, host, &flags, NULL, NULL);
    ret |= mbedtls_ssl_write(&ssl, (const unsigned char *)host, strlen(host));
    ret |= mbedtls_ssl_read(&ssl, buf, sizeof(buf));
    ret |= mbedtls_ssl_close_notify(&ssl);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_x509_crt_free(&ca);
    return ret;
}
#endif
