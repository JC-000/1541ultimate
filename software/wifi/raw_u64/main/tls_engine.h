/*
 * tls_engine.h
 *
 * TLS spike: TLS 1.3 client sessions whose ciphertext is carried by the
 * Ultimate. The ESP32 never touches a socket; every call is lock-step.
 */

#ifndef TLS_ENGINE_H_
#define TLS_ENGINE_H_

#include <stdint.h>
#include "rpc_calls.h"

#define TLS_HEAP_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) // what mbedTLS allocates from (esp_heap_caps.h)

typedef struct {
    uint32_t ct_in_bytes;
    uint32_t ct_out_bytes;
    uint32_t pt_in_bytes;
    uint32_t pt_out_bytes;
    uint32_t handshake_us;
    uint16_t tls_version;
    uint16_t ciphersuite;
    uint16_t group;
    uint8_t state;
    uint8_t time_source;
    uint32_t esp_time;
} tls_session_stats_t;

// All functions return ESP_OK, an esp_err_t, or a negative mbedTLS code.
// A session ends (and is freed) on FAILED, on CLOSED, on tls_close(), and when
// tls_open() finds the table full and evicts the least recently used session.

// unix_time sets the ESP32 clock when it is later than the build date. Verifying needs a
// trustworthy clock: without one OPEN fails with RPC_TLS_ERR_NO_TRUSTED_TIME.
int tls_open(uint8_t flags, const char *sni, int sni_len, uint32_t unix_time, uint8_t *session);

// Consumes all of ct_in (and pt_in, only when ESTABLISHED) or none of it, then
// writes ct_out followed by pt_out to out, together at most TLS_STEP_OUT_MAX.
// ESP_ERR_NO_MEM: a buffer is full, nothing was consumed, but output is returned;
// send the same input again. ESP_ERR_INVALID_ARG/INVALID_STATE/NOT_FOUND: nothing
// consumed, nothing returned. A negative code comes with state FAILED.
// out may overlap ct_in and pt_in: they are consumed (or refused) before out is written.
int tls_step(uint8_t session, const uint8_t *ct_in, int ct_in_len, const uint8_t *pt_in, int pt_in_len,
             uint8_t *out, uint16_t *ct_out_len, uint16_t *pt_out_len, uint8_t *state);

int tls_close(uint8_t session);
int tls_get_stats(uint8_t session, tls_session_stats_t *stats);
int tls_sessions_open(void);

#endif /* TLS_ENGINE_H_ */
