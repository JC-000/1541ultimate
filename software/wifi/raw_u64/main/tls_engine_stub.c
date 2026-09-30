/*
 * tls_engine_stub.c
 *
 * Stands in for tls_engine.c in a size-measurement build (idf.py -D BRIDGE_TLS_STUB=1): the RPC
 * commands stay, and every TLS call answers ESP_ERR_NOT_SUPPORTED, so mbedTLS's TLS and X.509 code
 * is not linked. Never flashed to a rig.
 */

#include "ndebug_guard.h" // first: refuses NDEBUG builds
#include <string.h>
#include "esp_err.h"
#include "tls_engine.h"

int tls_open(uint8_t flags, const char *sni, int sni_len, uint32_t unix_time, uint8_t *session, uint8_t *reason)
{
    (void)flags;
    (void)sni;
    (void)sni_len;
    (void)unix_time;
    *session = TLS_SESSION_GLOBAL;
    *reason = TLS_OPEN_REASON_NONE;
    return ESP_ERR_NOT_SUPPORTED;
}

int tls_step(uint8_t session, const uint8_t *ct_in, int ct_in_len, const uint8_t *pt_in, int pt_in_len,
             uint8_t *out, uint16_t *ct_out_len, uint16_t *pt_out_len, uint8_t *state)
{
    (void)session;
    (void)ct_in;
    (void)ct_in_len;
    (void)pt_in;
    (void)pt_in_len;
    (void)out;
    *ct_out_len = 0;
    *pt_out_len = 0;
    *state = TLS_STATE_CLOSED;
    return ESP_ERR_NOT_FOUND;
}

int tls_close(uint8_t session)
{
    (void)session;
    return ESP_ERR_NOT_FOUND;
}

int tls_get_stats(uint8_t session, tls_session_stats_t *stats)
{
    (void)session;
    memset(stats, 0, sizeof(tls_session_stats_t));
    stats->state = TLS_STATE_CLOSED;
    return ESP_ERR_NOT_SUPPORTED;
}

int tls_sessions_open(void)
{
    return 0;
}
