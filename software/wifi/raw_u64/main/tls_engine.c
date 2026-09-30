/*
 * tls_engine.c
 *
 * TLS spike (M2): the ESP32 runs mbedTLS as a TLS 1.3 client, and the
 * Ultimate pumps the ciphertext between its own TCP socket and CMD_TLS_STEP.
 * The bio callbacks never block: recv takes from a per-session input buffer
 * and send appends to a per-session output buffer.
 */

#include "ndebug_guard.h" // first: refuses NDEBUG builds
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif
#include "cmd_buffer.h"
#include "wifi_modem.h"
#include "sntp.h"
#include "tls_engine.h"
#include "tls_hello_scan.h"
#include "tls_group_cache.h"

#if !CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#error "The TLS spike is a TLS 1.3 client: enable CONFIG_MBEDTLS_SSL_PROTO_TLS1_3"
#endif
#if MBEDTLS_VERSION_MAJOR < 4
#error "This engine is written for mbedTLS 4 (ESP-IDF 6): randomness and allocation failures come from PSA"
#endif
#if !CONFIG_MBEDTLS_HAVE_TIME_DATE
#error "Without CONFIG_MBEDTLS_HAVE_TIME_DATE certificate dates are ignored: an expired certificate would verify"
#endif

// The test lane's root CA (scratchpad/esp-tls/m2-test-ca/test-ca.pem, DER SHA-256 c3d5f61f...), embedded by CMakeLists.txt.
extern const uint8_t tls_test_ca_pem_start[] asm("_binary_tls_test_ca_pem_start");
extern const uint8_t tls_test_ca_pem_end[]   asm("_binary_tls_test_ca_pem_end");

#ifndef TLS_IN_BUF_SIZE // a host test shrinks it to reach a full input buffer while handshaking
#define TLS_IN_BUF_SIZE  (2 * TLS_STEP_IN_MAX) // unread ciphertext from the Ultimate
#endif
#define TLS_OUT_BUF_SIZE 2048                  // ciphertext not yet collected by a step
// Step room kept free of plaintext for an alert that a failing read writes: header 5 + tag 16 +
// alert padded to at most 32 (CONFIG_MBEDTLS_SSL_CID_PADDING_GRANULARITY range 0..32) = 53
#define TLS_ALERT_ROOM   64
// NewSessionTickets one mbedtls_ssl_write() may run into; each is taken on its own, so this only bounds a loop
#define TLS_TICKET_RETRIES 4
// A session that nothing has touched (STEP, STATS, OPEN) for this long is an orphan: the Ultimate
// timed out on it and will never CLOSE it. The next OPEN reclaims it.
#define TLS_IDLE_RECLAIM_US (60LL * 1000 * 1000)
#define TLS_ID_GENERATIONS (TLS_SESSION_GLOBAL / TLS_MAX_SESSIONS)

_Static_assert(TLS_ID_GENERATIONS * TLS_MAX_SESSIONS <= TLS_SESSION_GLOBAL, "session ids must not reach 0xFF");
_Static_assert(TLS_OUT_BUF_SIZE > TLS_STEP_IN_MAX, "one step of plaintext must fit the output buffer");

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    uint8_t id;
    uint32_t last_used;
    int64_t last_touch_us; // esp_timer_get_time() at the last OPEN, STEP or STATS
    tls_session_stats_t stats;
    int in_off;
    int in_len;
    int out_len;
    uint64_t host_tag;      // tls_group_tag() of the SNI when this session may use the group cache, else 0
    uint8_t offered_default; // the offer is the default order (no entry, or a re-probe)
    uint8_t probe;          // a re-probe that has not completed: dropping the session drops the entry
    uint16_t groups[6];     // this session's offer, see tls_offer_groups()
    tls_hello_scan_t hello; // HRR and ServerHello groups, read from the bytes given to mbedTLS
    uint8_t in_buf[TLS_IN_BUF_SIZE];
    uint8_t out_buf[TLS_OUT_BUF_SIZE];
} tls_session_t;

static const char *TAG = "tls";
static tls_session_t *sessions[TLS_MAX_SESSIONS];
static uint8_t generation;
static uint32_t use_count;
static int psa_ready;
static int clock_set_by_nios;

// The default offer, with the group learned for this host (tls_group_cache.h) moved to the front
static void tls_offer_groups(tls_session_t *s)
{
    static const uint16_t base[] = {
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)
        0x11EC, // X25519MLKEM768: esp-pqc's fork defines the name, but app code sees IDF's stock ssl.h
#endif
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 };
    _Static_assert(sizeof(base) / sizeof(base[0]) < sizeof(((tls_session_t *)0)->groups) / sizeof(uint16_t),
                   "room for the terminator");
    int probe;
    s->offered_default = tls_group_offer(s->host_tag, base, sizeof(base) / sizeof(base[0]), s->groups, &probe);
    s->probe = probe;
}

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
    tls_hello_scan(&s->hello, buf, len);
    s->in_off += len;
    return (int)len;
}

#if CONFIG_TLS_SPIKE
// mbedTLS 3.6.0's TLS 1.3 client verifies whatever authmode says (ssl_tls13_validate_certificate()
// starts from VERIFY_REQUIRED and only a server reads conf->authmode), and it wants a CA chain.
// So "verify off" is an empty CA chain plus a callback that clears every verification flag.
// Spike builds only (CONFIG_TLS_SPIKE): anything else refuses to open without verification.
static int tls_accept_any(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx;
    (void)crt;
    (void)depth;
    *flags = 0;
    return 0;
}
#endif

// 00:00 UTC on the day this file was compiled: a clock before it cannot be right
static time_t tls_build_time(void)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *date = __DATE__; // "Mmm dd yyyy"
    int m = 1;
    while ((m < 12) && strncmp(months + 3 * (m - 1), date, 3)) {
        m++;
    }
    int d = atoi(date + 4);
    int y = atoi(date + 7) - (m <= 2);
    // Days since 1970-01-01 in the proleptic Gregorian calendar (days_from_civil)
    int era = y / 400;
    int yoe = y - era * 400;
    int doy = (153 * (m + ((m > 2) ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (time_t)(era * 146097 + doe - 719468) * 86400;
}

// The clock a verifying OPEN may use. SNTP wins: the Ultimate's unix_time can come from an RTC
// that is hours off, so it is only taken when the ESP32 has no SNTP time. Reports the source
// used for this OPEN; a clock an earlier OPEN set does not count (unix_time 0 means none).
static uint8_t tls_set_clock(uint32_t unix_time)
{
    time_t floor = tls_build_time();
    if (sntp_has_time() && (time(NULL) > floor)) {
        return TLS_TIME_SNTP;
    }
    if ((time_t)unix_time > floor) {
        struct timeval tv = { .tv_sec = (time_t)unix_time, .tv_usec = 0 };
        if (settimeofday(&tv, NULL) == 0) {
            clock_set_by_nios = 1;
            return TLS_TIME_NIOS;
        }
    }
    return TLS_TIME_NONE;
}

static tls_session_t *tls_find(uint8_t id)
{
    tls_session_t *s = sessions[id % TLS_MAX_SESSIONS];
    return (s && (s->id == id)) ? s : NULL;
}

static void tls_free(tls_session_t *s)
{
    // A session that failed to open never took its slot, which may still hold the one it would evict
    if (sessions[s->id % TLS_MAX_SESSIONS] == s) {
        sessions[s->id % TLS_MAX_SESSIONS] = NULL;
    }
    if (s->probe) { // a re-probe that failed or was abandoned: back to the default order for this host
        tls_group_forget(s->host_tag);
    }
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    mbedtls_x509_crt_free(&s->ca);
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

// Set-up failures that another session's memory could cure
static int tls_out_of_memory(int ret)
{
    if (ret == ESP_ERR_NO_MEM) {
        return 1;
    }
    if (ret >= 0) {
        return 0;
    }
    // mbedTLS 4 reports every allocation failure (SSL, X.509, PK, PEM, ASN.1, bignum) as this one
    // PSA code, and no longer adds a low-level code to a high-level one (private/error_common.h)
    return ret == PSA_ERROR_INSUFFICIENT_MEMORY;
}

// Builds a complete session for slot without putting it in the table; frees it on failure
static int tls_setup(tls_session_t **out, int slot, int verify, int cas, const char *hostname, int sni_len,
                     uint8_t time_source)
{
    *out = NULL;
    tls_session_t *s = calloc(1, sizeof(tls_session_t));
    if (!s) {
        return ESP_ERR_NO_MEM;
    }
    s->id = (generation * TLS_MAX_SESSIONS) + slot;
    generation = (generation + 1) % TLS_ID_GENERATIONS;
    s->stats.state = TLS_STATE_HANDSHAKING;
    s->stats.time_source = time_source;
    s->stats.esp_time = (time_source == TLS_TIME_NONE) ? 0 : (uint32_t)time(NULL);
    s->last_used = ++use_count;
    s->last_touch_us = esp_timer_get_time();
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->ca);

    // Every random byte (client random, key shares) comes from PSA: see tls_open()
    int ret = mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret == 0) {
        // ESP-IDF 6 always builds TLS 1.2 in (MBEDTLS_TLS_ENABLED selects it): only these two keep it out
        mbedtls_ssl_conf_min_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
        // mbedTLS 4's default list adds x448 and FFDHE 2048-8192 (an 8192-bit modexp on the ESP32):
        // offer what mbedTLS 3.6.0 offered here, in its order. mbedTLS keeps the pointer: it is the session's.
        s->host_tag = tls_group_session_tag(verify, cas, TLS_OPEN_CA_BUNDLE, hostname, sni_len);
        tls_offer_groups(s);
        mbedtls_ssl_conf_groups(&s->conf, s->groups);
        mbedtls_ssl_conf_authmode(&s->conf, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
#if CONFIG_TLS_SPIKE
        if (!verify) {
            mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca, NULL);
            mbedtls_ssl_conf_verify(&s->conf, tls_accept_any, NULL);
        }
#endif
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
        s->probe = 0; // never started: the probe is offered again by the next OPEN
        tls_free(s);
        return ret;
    }
    mbedtls_ssl_set_bio(&s->ssl, s, tls_bio_send, tls_bio_recv, NULL);
    *out = s;
    return 0;
}

int tls_open(uint8_t flags, const char *sni, int sni_len, uint32_t unix_time, uint8_t *session, uint8_t *reason)
{
    char hostname[TLS_SNI_MAX_LEN + 1];
    int verify = flags & TLS_OPEN_VERIFY;
    int cas = flags & (TLS_OPEN_CA_BUNDLE | TLS_OPEN_CA_TEST);

    *session = TLS_SESSION_GLOBAL;
    *reason = TLS_OPEN_REASON_NONE;
    // Verifying without a host name would skip the name check, so it is refused
    if ((flags & ~(TLS_OPEN_VERIFY | TLS_OPEN_CA_BUNDLE | TLS_OPEN_CA_TEST)) ||
        (verify && ((cas != TLS_OPEN_CA_BUNDLE) && (cas != TLS_OPEN_CA_TEST))) ||
        (verify && (sni_len == 0)) || (sni_len < 0) || (sni_len > TLS_SNI_MAX_LEN) ||
        (memchr(sni, 0, sni_len) != NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
#if !CONFIG_TLS_SPIKE
    if (!verify) {
        return ESP_ERR_NOT_SUPPORTED;
    }
#endif
    if (entropy_source() == ENTROPY_NONE) {
        *reason = TLS_OPEN_REASON_NO_ENTROPY;
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t time_source = tls_set_clock(unix_time);
    if (verify && (time_source == TLS_TIME_NONE)) {
        // Never verify against a 1970 clock: every validity check would be meaningless
        ESP_LOGW(TAG, "Open refused: verify needs a clock, and neither unix_time nor SNTP gave one");
        *reason = TLS_OPEN_REASON_NO_TIME;
        return ESP_ERR_INVALID_STATE;
    }
#if !CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (verify && (cas == TLS_OPEN_CA_BUNDLE)) {
        return ESP_ERR_NOT_SUPPORTED;
    }
#endif
    // All randomness comes from PSA. ESP-IDF 6 has already run psa_crypto_init() at startup, before
    // the radio, but with MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG: PSA keeps no seeded state and draws every
    // byte from esp_fill_random() when it is needed. A session draws only after this entropy gate,
    // and the radio then stays on, so the gate still decides (M2-SPEC section 8). This init is then
    // a no-op; it stays for builds that do not initialise PSA at startup.
    if (!psa_ready) {
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS) {
            ESP_LOGE(TAG, "psa_crypto_init: %d", (int)status);
            return ESP_FAIL;
        }
        psa_ready = 1;
    }
    memcpy(hostname, sni, sni_len);
    hostname[sni_len] = 0;

    // Orphans (the Ultimate timed out on an OPEN or CLOSE) would otherwise live until a full table
    int64_t now_us = esp_timer_get_time();
    for (int i = 0; i < TLS_MAX_SESSIONS; i++) {
        if (sessions[i] && (now_us - sessions[i]->last_touch_us > TLS_IDLE_RECLAIM_US)) {
            ESP_LOGW(TAG, "Reclaiming session %d, idle for %lld s", sessions[i]->id,
                     (long long)((now_us - sessions[i]->last_touch_us) / 1000000));
            tls_free(sessions[i]);
        }
    }

    // A full table evicts the least recently used session, so orphans cannot lock TLS out.
    // The victim goes only once the new session is fully set up, so a failed OPEN kills nothing,
    // except when the set-up ran out of memory: then the victim goes and the set-up runs once more.
    int slot = -1;
    for (int i = 0; i < TLS_MAX_SESSIONS; i++) {
        if (!sessions[i]) {
            slot = i;
            break;
        }
    }
    tls_session_t *victim = NULL;
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < TLS_MAX_SESSIONS; i++) {
            if (sessions[i]->last_used < sessions[slot]->last_used) {
                slot = i;
            }
        }
        victim = sessions[slot];
    }
    if (tls_sessions_open() == 0) {
        // heap_min then reports the peak of this burst of sessions, not of the Wi-Fi start
        heap_caps_monitor_local_minimum_free_size_stop();
        heap_caps_monitor_local_minimum_free_size_start();
    }

    tls_session_t *s = NULL;
    int ret = tls_setup(&s, slot, verify, cas, hostname, sni_len, time_source);
    if ((ret != 0) && victim && tls_out_of_memory(ret)) {
        ESP_LOGW(TAG, "No memory for a new session: evicting session %d and trying again", victim->id);
        tls_free(victim);
        victim = NULL;
        ret = tls_setup(&s, slot, verify, cas, hostname, sni_len, time_source);
    }
    if (ret != 0) {
        return ret;
    }
    if (victim) {
        ESP_LOGW(TAG, "Table full, evicting session %d", victim->id);
        tls_free(victim);
    }
    sessions[slot] = s;
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
    s->last_touch_us = esp_timer_get_time();

    if (!refused && (ret == 0)) {
        if (s->in_off) {
            memmove(s->in_buf, s->in_buf + s->in_off, s->in_len - s->in_off);
            s->in_len -= s->in_off;
            s->in_off = 0;
        }
        memcpy(s->in_buf + s->in_len, ct_in, ct_in_len);
        s->in_len += ct_in_len;
        s->stats.ct_in_bytes += ct_in_len;
    }
    // While handshaking only mbedtls_ssl_handshake() drains in_buf, so it also runs when the input
    // was refused: otherwise a full in_buf would refuse every resend of the step
    if (ret == 0) {
        if (s->stats.state == TLS_STATE_HANDSHAKING) {
            int64_t start = esp_timer_get_time();
            ret = mbedtls_ssl_handshake(&s->ssl);
            s->stats.handshake_us += (uint32_t)(esp_timer_get_time() - start);
            if (ret == 0) {
                s->stats.state = TLS_STATE_ESTABLISHED;
                s->stats.tls_version = (uint16_t)mbedtls_ssl_get_version_number(&s->ssl);
                s->stats.ciphersuite = (uint16_t)mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl);
                // No public mbedTLS call gives the negotiated group: stats.group stays 0
                tls_group_learn(s->host_tag, s->hello.saw_hrr, s->hello.chosen, s->offered_default);
                s->probe = 0;
            } else if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                ret = 0;
            }
        } else if (!refused && pt_in_len) {
            if (s->ssl.MBEDTLS_PRIVATE(out_left) != 0) {
                ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
            for (int done = 0, tickets = 0; (ret == 0) && (done < pt_in_len); ) {
                int n = mbedtls_ssl_write(&s->ssl, pt_in + done, pt_in_len - done);
                if (n > 0) {
                    done += n;
                } else if ((n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) && (++tickets <= TLS_TICKET_RETRIES)) {
                    // A ticket an earlier read left pending: mbedtls_ssl_write() took it first and wrote
                    // nothing, so write again (ssl_msg.c:5938-5942 in mbedTLS 4.1.1). Not a failure.
                    continue;
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
    while ((ret == 0) && (s->stats.state == TLS_STATE_ESTABLISHED) &&
           (ct_len + pt_len + TLS_ALERT_ROOM < TLS_STEP_OUT_MAX)) {
        int n = mbedtls_ssl_read(&s->ssl, out + ct_len + pt_len, TLS_STEP_OUT_MAX - TLS_ALERT_ROOM - ct_len - pt_len);
        if (n > 0) {
            pt_len += n;
        } else if ((n == MBEDTLS_ERR_SSL_WANT_READ) && mbedtls_ssl_check_pending(&s->ssl)) {
            // A complete ticket makes mbedtls_ssl_read() return WANT_READ with the ticket kept for the
            // next call (ssl_msg.c:5466-5473 in mbedTLS 4.1.1), which takes it without new input.
            // Take every one now, or the reply behind them waits for a step the Ultimate never sends.
            continue;
        } else if ((n == MBEDTLS_ERR_SSL_WANT_READ) || (n == MBEDTLS_ERR_SSL_WANT_WRITE)) {
            // Known limitation: a skipped warning alert (no_renegotiation, not TLS 1.3) ends up here with input left
            break;
        } else if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue; // a TLS 1.3 ticket after the handshake: no plaintext yet, read again (never FAILED)
        } else if (n == 0) {
            // An empty application data record, which RFC 8446 allows: read on. It never means the
            // connection closed, because tls_bio_recv() never reports end of input.
            continue;
        } else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            s->stats.state = TLS_STATE_CLOSED;
        } else {
            ret = n;
        }
    }
    s->stats.pt_out_bytes += pt_len;

    // Ciphertext the reads produced (a fatal alert before the session is freed) goes out in this
    // step too: move the plaintext up into the room the reads left for it
    int ct_all = (s->out_len < TLS_STEP_OUT_MAX - pt_len) ? s->out_len : TLS_STEP_OUT_MAX - pt_len;
    if (ct_all > ct_len) {
        memmove(out + ct_all, out + ct_len, pt_len);
        ct_len = ct_all;
    }
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
        time_t now = time(NULL);
        if (now <= tls_build_time()) {
            stats->time_source = TLS_TIME_NONE;
        } else {
            stats->time_source = sntp_has_time() ? TLS_TIME_SNTP : (clock_set_by_nios ? TLS_TIME_NIOS : TLS_TIME_NONE);
        }
        stats->esp_time = (stats->time_source == TLS_TIME_NONE) ? 0 : (uint32_t)now;
        return ESP_OK;
    }
    tls_session_t *s = tls_find(session);
    if (!s) {
        return ESP_ERR_NOT_FOUND;
    }
    s->last_touch_us = esp_timer_get_time();
    *stats = s->stats;
    return ESP_OK;
}
