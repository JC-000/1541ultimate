/*
 * wifi_tls.h
 *
 * TLS sessions that run on the WiFi module (esp-tls M2 spike). The module
 * holds the keys and runs the protocol; this side carries the ciphertext
 * between a socket and the module, one step at a time, and the module never
 * speaks unasked. U64 only.
 *
 * Kept apart from wifi_cmd.h, like wifi_random.h, so that its users do not see
 * the module's RPC definitions in rpc_calls.h; wifi_tls.cc asserts that the
 * values repeated here match them.
 */

#ifndef WIFI_TLS_H_
#define WIFI_TLS_H_

#include <stdint.h>

#define WIFI_TLS_FLAG_VERIFY    0x01 // verify the server's chain and name
#define WIFI_TLS_FLAG_CA_BUNDLE 0x02 // trust the CA bundle
#define WIFI_TLS_FLAG_TEST_CA   0x04 // trust the built in test CA
#define WIFI_TLS_SESSION_GLOBAL 0xFF // for wifi_tls_stats: the module as a whole
#define WIFI_TLS_MAX_SNI        255
#define WIFI_TLS_STEP_MAX_IN    1024 // ct_in_len + pt_in_len in one step

#define WIFI_TLS_HANDSHAKING    0
#define WIFI_TLS_ESTABLISHED    1
#define WIFI_TLS_CLOSED         2
#define WIFI_TLS_FAILED         3 // esp_err holds the mbedTLS error
#define WIFI_TLS_UNKNOWN        0xFF // the answer did not say

// What the calls below return besides 0.
#define WIFI_TLS_BUSY      1 // sent, but no answer in time; the module may still act on it
#define WIFI_TLS_REFUSED   2 // the module answered with an error, which is in esp_err
#define WIFI_TLS_INVALID   3 // the answer is not a well formed reply
#define WIFI_TLS_NO_MODULE 4 // the module application is not running; nothing was sent
#define WIFI_TLS_FOREIGN   5 // (from the checks only) not the answer to this request
#define WIFI_TLS_UNSENT    6 // another request was outstanding, or no buffer; nothing was sent
#define WIFI_TLS_TOO_LONG  7 // the request does not fit; nothing was sent

typedef struct {
    uint32_t heap_free;
    uint32_t heap_min_ever;
    uint32_t largest_block;
    uint32_t ct_in_bytes; // the session's counters; 0 for the module as a whole
    uint32_t ct_out_bytes;
    uint32_t pt_in_bytes;
    uint32_t pt_out_bytes;
    uint32_t handshake_us;
    uint16_t tls_version; // as on the wire: 0x0304 is TLS 1.3
    uint16_t ciphersuite; // IANA number
    uint16_t group;       // IANA NamedGroup
} wifi_tls_stats_t;

// One step: the module takes all of ct_in, and pt_in once the session is
// established, and hands back what it has ready, up to a reply's worth. The
// caller sets the first block and the module's answer fills the second.
//
// A handshake that fails is an answer, not an error: the call returns 0 with
// state FAILED and the mbedTLS error in esp_err, and ct_out may hold the alert
// for the server. REFUSED is for an error in any other state. Nothing is
// written to ct_out or pt_out unless the call returns 0, and plaintext only
// ever comes from a session that is ESTABLISHED or has just been CLOSED.
typedef struct {
    const uint8_t *ct_in;
    uint16_t ct_in_len;
    const uint8_t *pt_in;
    uint16_t pt_in_len;
    uint8_t *ct_out;
    uint16_t ct_out_room;
    uint8_t *pt_out;
    uint16_t pt_out_room;

    uint16_t ct_out_len;
    uint16_t pt_out_len;
    uint8_t state;        // WIFI_TLS_HANDSHAKING .. WIFI_TLS_FAILED, or WIFI_TLS_UNKNOWN
    int esp_err;
} wifi_tls_step_t;

// Each returns 0 or one of the codes above. esp_err, where there is one, is
// set to 0 first and to the module's error when it answered with one.
int wifi_tls_open(uint8_t flags, const char *sni, uint8_t *session, int *esp_err);
int wifi_tls_step(uint8_t session, wifi_tls_step_t *step);
int wifi_tls_close(uint8_t session, int *esp_err);
int wifi_tls_stats(uint8_t session, wifi_tls_stats_t *stats, int *esp_err);

// The checks the calls above apply to the module's answer to request
// sequence, apart so that the host can test them. Each returns 0 for the
// answer, WIFI_TLS_FOREIGN for a reply to something else, and REFUSED or
// INVALID otherwise, and writes its outputs as described above.
int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, uint8_t *session, int *esp_err);
int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step);
int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, int *esp_err);
int wifi_tls_take_stats(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_stats_t *stats, int *esp_err);

#ifdef TLS_SPIKE
// The spike: connects to host:port, runs a handshake through the module, sends
// echo bytes of plaintext and reads them back, and closes the session and the
// socket whatever happened. Spike code, not for release.
#define WIFI_TLS_SPIKE_MAX_ECHO 65536

typedef struct {
    bool ok;
    const char *stage;   // where it ended: "done" when ok
    int error;           // what ended it: a WIFI_TLS_* code for "open", "*_step" and "close",
                         // a state for "*_state", 0 for "echo_compare", an errno otherwise
    int esp_err;         // the module's error at that point, if any
    int state;           // the last session state seen, -1 before OPEN
    int steps;           // STEP calls, handshake and echo
    int handshake_steps;
    uint32_t handshake_ms; // from OPEN to ESTABLISHED, on this side's tick
    bool have_before, have_peak, have_after;
    int stats_error;     // the last STATS call that failed, if any
    wifi_tls_stats_t before; // the module, before the socket is opened
    wifi_tls_stats_t peak;   // the session, just after ESTABLISHED
    wifi_tls_stats_t after;  // the module, after the session is closed
    uint32_t tcp_out;    // ciphertext bytes sent to the server
    uint32_t tcp_in;     // ciphertext bytes received from the server
    int echo_sent;
    int echo_received;
    int early_plaintext; // plaintext bytes that came before any were sent
    bool echo_ok;
    bool session_opened;
    int close_result;    // of CLOSE, when session_opened
    bool socket_opened;
} wifi_tls_spike_result_t;

void wifi_tls_spike(const char *host, uint16_t port, const char *sni, uint8_t flags, int echo,
                    wifi_tls_spike_result_t *result);
#endif

#endif /* WIFI_TLS_H_ */
