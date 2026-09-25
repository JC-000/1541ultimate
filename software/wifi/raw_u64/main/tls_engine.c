/*
 * tls_engine.c
 *
 * TLS spike (M2): the ESP32 runs mbedTLS as a TLS 1.3 client, and the
 * Ultimate pumps the ciphertext between its own TCP socket and CMD_TLS_STEP.
 * The bio callbacks never block: recv takes from a per-session input buffer
 * and send appends to a per-session output buffer.
 */

#include <string.h>
#include <stdlib.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif
#include "cmd_buffer.h"
#include "wifi_modem.h"
#include "tls_engine.h"

#if !CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#error "The TLS spike is a TLS 1.3 client: enable CONFIG_MBEDTLS_SSL_PROTO_TLS1_3"
#endif

// Drop the test lane's CA certificate (PEM) into main/tls_test_ca.pem.
extern const uint8_t tls_test_ca_pem_start[] asm("_binary_tls_test_ca_pem_start");
extern const uint8_t tls_test_ca_pem_end[]   asm("_binary_tls_test_ca_pem_end");

#define TLS_IN_BUF_SIZE  (2 * TLS_STEP_IN_MAX) // unread ciphertext from the Ultimate
#define TLS_OUT_BUF_SIZE 2048                  // ciphertext not yet collected by a step
#define TLS_ID_GENERATIONS (TLS_SESSION_GLOBAL / TLS_MAX_SESSIONS)

_Static_assert(TLS_ID_GENERATIONS * TLS_MAX_SESSIONS <= TLS_SESSION_GLOBAL, "session ids must not reach 0xFF");
_Static_assert(TLS_OUT_BUF_SIZE > TLS_STEP_IN_MAX, "one step of plaintext must fit the output buffer");

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt ca;
    uint8_t id;
    uint32_t last_used;
    tls_session_stats_t stats;
    int in_off;
    int in_len;
    int out_len;
    uint8_t in_buf[TLS_IN_BUF_SIZE];
    uint8_t out_buf[TLS_OUT_BUF_SIZE];
} tls_session_t;

static const char *TAG = "tls";
static tls_session_t *sessions[TLS_MAX_SESSIONS];
static uint8_t generation;
static uint32_t use_count;

static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    tls_session_t *s = (tls_session_t *)ctx;
    size_t room = TLS_OUT_BUF_SIZE - s->out_len;
    if (room == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (len > room) {
        len = room;
    }
    memcpy(s->out_buf + s->out_len, buf, len);
    s->out_len += len;
    return (int)len;
}

static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    tls_session_t *s = (tls_session_t *)ctx;
    size_t avail = s->in_len - s->in_off;
    if (avail == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (len > avail) {
        len = avail;
    }
    memcpy(buf, s->in_buf + s->in_off, len);
    s->in_off += len;
    return (int)len;
}

// mbedTLS 3.6.0's TLS 1.3 client verifies whatever authmode says (ssl_tls13_validate_certificate()
// starts from VERIFY_REQUIRED and only a server reads conf->authmode), and it wants a CA chain.
// So "verify off" is an empty CA chain plus a callback that clears every verification flag.
static int tls_accept_any(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx;
    (void)crt;
    (void)depth;
    *flags = 0;
    return 0;
}

static tls_session_t *tls_find(uint8_t id)
{
    tls_session_t *s = sessions[id % TLS_MAX_SESSIONS];
    return (s && (s->id == id)) ? s : NULL;
}

static void tls_free(tls_session_t *s)
{
    sessions[s->id % TLS_MAX_SESSIONS] = NULL;
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    mbedtls_x509_crt_free(&s->ca);
    mbedtls_ctr_drbg_free(&s->drbg);
    mbedtls_entropy_free(&s->entropy);
    // The certificate bundle is shared: esp_crt_bundle_detach() would free it under the other session
    free(s);
}

int tls_sessions_open(void)
{
    int n = 0;
    for (int i = 0; i < TLS_MAX_SESSIONS; i++) {
        if (sessions[i]) {
            n++;
        }
    }
    return n;
}

int tls_open(uint8_t flags, const char *sni, int sni_len, uint8_t *session)
{
    char hostname[TLS_SNI_MAX_LEN + 1];
    int verify = flags & TLS_OPEN_VERIFY;
    int cas = flags & (TLS_OPEN_CA_BUNDLE | TLS_OPEN_CA_TEST);

    *session = TLS_SESSION_GLOBAL;
    // Verifying without a host name would skip the name check, so it is refused
    if ((flags & ~(TLS_OPEN_VERIFY | TLS_OPEN_CA_BUNDLE | TLS_OPEN_CA_TEST)) ||
        (verify && ((cas != TLS_OPEN_CA_BUNDLE) && (cas != TLS_OPEN_CA_TEST))) ||
        (verify && (sni_len == 0)) || (sni_len < 0) || (sni_len > TLS_SNI_MAX_LEN) ||
        (memchr(sni, 0, sni_len) != NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (entropy_source() == ENTROPY_NONE) {
        return ESP_ERR_INVALID_STATE;
    }
#if !CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (verify && (cas == TLS_OPEN_CA_BUNDLE)) {
        return ESP_ERR_NOT_SUPPORTED;
    }
#endif
    // TLS 1.3 key shares come from the PSA RNG, not from the session DRBG. It seeds itself
    // from the hardware RNG on its first init, so that must not happen before the radio runs.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init: %d", (int)status);
        return ESP_FAIL;
    }
    memcpy(hostname, sni, sni_len);
    hostname[sni_len] = 0;

    // A full table evicts the least recently used session, so orphans cannot lock TLS out
    int slot = -1;
    for (int i = 0; i < TLS_MAX_SESSIONS; i++) {
        if (!sessions[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < TLS_MAX_SESSIONS; i++) {
            if (sessions[i]->last_used < sessions[slot]->last_used) {
                slot = i;
            }
        }
        ESP_LOGW(TAG, "Table full, evicting session %d", sessions[slot]->id);
        tls_free(sessions[slot]);
    }
    if (tls_sessions_open() == 0) {
        // heap_min then reports the peak of this burst of sessions, not of the Wi-Fi start
        heap_caps_monitor_local_minimum_free_size_stop();
        heap_caps_monitor_local_minimum_free_size_start();
    }

    tls_session_t *s = calloc(1, sizeof(tls_session_t));
    if (!s) {
        return ESP_ERR_NO_MEM;
    }
    s->id = (generation * TLS_MAX_SESSIONS) + slot;
    generation = (generation + 1) % TLS_ID_GENERATIONS;
    s->stats.state = TLS_STATE_HANDSHAKING;
    s->last_used = ++use_count;
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->ca);
    mbedtls_ctr_drbg_init(&s->drbg);
    mbedtls_entropy_init(&s->entropy);
    sessions[slot] = s;

    static const char pers[] = "u64 tls spike";
    int ret = mbedtls_ctr_drbg_seed(&s->drbg, mbedtls_entropy_func, &s->entropy,
                                    (const unsigned char *)pers, sizeof(pers) - 1);
    if (ret == 0) {
        ret = mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (ret == 0) {
        mbedtls_ssl_conf_min_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->drbg);
        mbedtls_ssl_conf_authmode(&s->conf, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
        if (!verify) {
            mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca, NULL);
            mbedtls_ssl_conf_verify(&s->conf, tls_accept_any, NULL);
        }
        if (verify && (cas == TLS_OPEN_CA_TEST)) {
            ret = mbedtls_x509_crt_parse(&s->ca, tls_test_ca_pem_start, tls_test_ca_pem_end - tls_test_ca_pem_start);
            if (ret > 0) {
                ret = MBEDTLS_ERR_X509_INVALID_FORMAT; // some certificates did not parse
            }
            if (ret == 0) {
                mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca, NULL);
            }
        }
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        if (verify && (cas == TLS_OPEN_CA_BUNDLE)) {
            ret = esp_crt_bundle_attach(&s->conf);
        }
#endif
    }
    if (ret == 0) {
        ret = mbedtls_ssl_setup(&s->ssl, &s->conf);
    }
    if ((ret == 0) && sni_len) {
        ret = mbedtls_ssl_set_hostname(&s->ssl, hostname);
    }
    if (ret != 0) {
        ESP_LOGW(TAG, "Open failed: -0x%04x", (unsigned)-ret);
        tls_free(s);
        return ret;
    }
    mbedtls_ssl_set_bio(&s->ssl, s, tls_bio_send, tls_bio_recv, NULL);
    *session = s->id;
    return ESP_OK;
}

int tls_step(uint8_t session, const uint8_t *ct_in, int ct_in_len, const uint8_t *pt_in, int pt_in_len,
             uint8_t *out, uint16_t *ct_out_len, uint16_t *pt_out_len, uint8_t *state)
{
    tls_session_t *s = tls_find(session);
    *ct_out_len = 0;
    *pt_out_len = 0;
    if (!s) {
        *state = TLS_STATE_CLOSED;
        return ESP_ERR_NOT_FOUND;
    }
    *state = s->stats.state;

    // Caller errors consume nothing, return nothing and leave the session as it is
    if ((ct_in_len < 0) || (pt_in_len < 0) || (ct_in_len + pt_in_len > TLS_STEP_IN_MAX)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pt_in_len && (s->stats.state != TLS_STATE_ESTABLISHED)) {
        return ESP_ERR_INVALID_STATE;
    }
    // A full buffer refuses the input with ESP_ERR_NO_MEM, but the step still returns output,
    // so the Ultimate can send the same step again until it is taken
    int ret = 0;
    int refused = (ct_in_len > TLS_IN_BUF_SIZE - (s->in_len - s->in_off)) ? ESP_ERR_NO_MEM : ESP_OK;
    if (!refused && pt_in_len) {
        // mbedtls_ssl_write() must never see WANT_WRITE: it would keep part of pt_in for a
        // repeat call, and with output pending it reports len written without copying it
        int payload = mbedtls_ssl_get_max_out_record_payload(&s->ssl);
        int expansion = mbedtls_ssl_get_record_expansion(&s->ssl);
        if (payload <= 0) {
            ret = payload ? payload : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        } else if (expansion < 0) {
            ret = expansion;
        } else {
            int need = pt_in_len + ((pt_in_len + payload - 1) / payload) * expansion;
            if (need > TLS_OUT_BUF_SIZE) {
                return ESP_ERR_INVALID_ARG; // could never fit: send less plaintext per step
            }
            if (need > TLS_OUT_BUF_SIZE - s->out_len) {
                refused = ESP_ERR_NO_MEM;
            }
        }
    }
    s->last_used = ++use_count;

    if (!refused && (ret == 0)) {
        if (s->in_off) {
            memmove(s->in_buf, s->in_buf + s->in_off, s->in_len - s->in_off);
            s->in_len -= s->in_off;
            s->in_off = 0;
        }
        memcpy(s->in_buf + s->in_len, ct_in, ct_in_len);
        s->in_len += ct_in_len;
        s->stats.ct_in_bytes += ct_in_len;

        if (s->stats.state == TLS_STATE_HANDSHAKING) {
            int64_t start = esp_timer_get_time();
            ret = mbedtls_ssl_handshake(&s->ssl);
            s->stats.handshake_us += (uint32_t)(esp_timer_get_time() - start);
            if (ret == 0) {
                s->stats.state = TLS_STATE_ESTABLISHED;
                s->stats.tls_version = (uint16_t)mbedtls_ssl_get_version_number(&s->ssl);
                s->stats.ciphersuite = (uint16_t)mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl);
                // No public mbedTLS 3.6 call gives the negotiated group: stats.group stays 0
            } else if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                ret = 0;
            }
        } else if (pt_in_len) {
            if (s->ssl.MBEDTLS_PRIVATE(out_left) != 0) {
                ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
            for (int done = 0; (ret == 0) && (done < pt_in_len); ) {
                int n = mbedtls_ssl_write(&s->ssl, pt_in + done, pt_in_len - done);
                if (n > 0) {
                    done += n;
                } else {
                    ret = n ? n : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                }
            }
            if (ret == 0) {
                s->stats.pt_in_bytes += pt_in_len;
            }
        }
    }
    // From here on out may be written: the input is either consumed or refused

    int ct_len = (s->out_len < TLS_STEP_OUT_MAX) ? s->out_len : TLS_STEP_OUT_MAX;
    int pt_len = 0;
    while ((ret == 0) && (s->stats.state == TLS_STATE_ESTABLISHED) && (ct_len + pt_len < TLS_STEP_OUT_MAX)) {
        int n = mbedtls_ssl_read(&s->ssl, out + ct_len + pt_len, TLS_STEP_OUT_MAX - ct_len - pt_len);
        if (n > 0) {
            pt_len += n;
        } else if ((n == MBEDTLS_ERR_SSL_WANT_READ) || (n == MBEDTLS_ERR_SSL_WANT_WRITE)) {
            break;
        } else if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue;
        } else if ((n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) || (n == 0)) {
            s->stats.state = TLS_STATE_CLOSED;
        } else {
            ret = n;
        }
    }
    s->stats.pt_out_bytes += pt_len;

    memcpy(out, s->out_buf, ct_len);
    memmove(s->out_buf, s->out_buf + ct_len, s->out_len - ct_len);
    s->out_len -= ct_len;
    s->stats.ct_out_bytes += ct_len;
    *ct_out_len = ct_len;
    *pt_out_len = pt_len;

    if (ret != 0) {
        s->stats.state = TLS_STATE_FAILED;
        ESP_LOGW(TAG, "Session %d failed: -0x%04x, verify 0x%x", s->id, (unsigned)-ret,
                 (unsigned)mbedtls_ssl_get_verify_result(&s->ssl));
    }
    *state = s->stats.state;
    if ((s->stats.state == TLS_STATE_FAILED) || (s->stats.state == TLS_STATE_CLOSED)) {
        tls_free(s);
    }
    return ret ? ret : refused;
}

int tls_close(uint8_t session)
{
    tls_session_t *s = tls_find(session);
    if (!s) {
        return ESP_ERR_NOT_FOUND;
    }
    tls_free(s);
    return ESP_OK;
}

int tls_get_stats(uint8_t session, tls_session_stats_t *stats)
{
    memset(stats, 0, sizeof(tls_session_stats_t));
    stats->state = TLS_STATE_CLOSED;
    if (session == TLS_SESSION_GLOBAL) {
        return ESP_OK;
    }
    tls_session_t *s = tls_find(session);
    if (!s) {
        return ESP_ERR_NOT_FOUND;
    }
    *stats = s->stats;
    return ESP_OK;
}
