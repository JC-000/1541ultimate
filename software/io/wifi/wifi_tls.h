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
#define WIFI_TLS_MAX_SNI        253
#define WIFI_TLS_STEP_MAX_IN    1536 // ct_in_len + pt_in_len in one step

// Why an OPEN was refused with ESP_ERR_INVALID_STATE.
#define WIFI_TLS_REASON_NO_ENTROPY 1 // the radio has not started, so there is no seed
#define WIFI_TLS_REASON_NO_TIME    2 // verify asked for, and neither side has a trustworthy clock

// Where the module's clock came from.
#define WIFI_TLS_TIME_NONE 0
#define WIFI_TLS_TIME_NIOS 1 // unix_time in an OPEN
#define WIFI_TLS_TIME_SNTP 2 // the module's own SNTP

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
#define WIFI_TLS_AGAIN     8 // STEP only: the module had no room and did not take the input, but its
                             // output is handed over as for 0; send the same input again

typedef struct {
    uint32_t heap_free;
    uint32_t heap_min_ever; // the module's low-water mark since the OPEN that found no session open
    uint32_t largest_block;
    uint32_t ct_in_bytes; // the session's counters; 0 for the module as a whole
    uint32_t ct_out_bytes;
    uint32_t pt_in_bytes;
    uint32_t pt_out_bytes;
    uint32_t handshake_us;
    uint16_t tls_version; // as on the wire: 0x0304 is TLS 1.3
    uint16_t ciphersuite; // IANA number
    uint16_t group;       // IANA NamedGroup; 0, unknown, from mbedTLS 3.6
    uint8_t state;
    uint8_t sessions_open;
    uint32_t stack_free;  // the module's dispatcher stack, least ever free
    uint32_t esp_time;    // the module's clock at the session's OPEN (now, for the module)
    uint8_t time_source;  // WIFI_TLS_TIME_*
} wifi_tls_stats_t;

// One step: the module takes all of ct_in, and pt_in once the session is
// established, and hands back what it has ready, up to a reply's worth. The
// caller sets the first block and the module's answer fills the second.
//
// The module takes the input all or nothing. When it has no room it answers
// ESP_ERR_NO_MEM with its output all the same: the call returns AGAIN, hands the
// output over, and the same input is to be sent again. If that answer also says
// CLOSED, the peer has closed and the refusal no longer matters: the call
// returns 0 with state CLOSED and the output, the last plaintext included.
//
// A session that fails is an answer, not an error: the call returns 0 with state
// FAILED and the mbedTLS error in esp_err, and ct_out may hold the alert for the
// server. The module has then freed the session, as it has after CLOSED.
// REFUSED is for an error in any other state. Nothing is written to ct_out or
// pt_out unless the call returns 0 or AGAIN, and plaintext only ever comes from
// a session that is ESTABLISHED or has just been CLOSED; what a FAILED answer
// carries is withheld.
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
// unix_time is UTC seconds from this side's clock, 0 when it has none. reason is
// set to 0 first, and to WIFI_TLS_REASON_* when the module says why it refused.
int wifi_tls_open(uint8_t flags, const char *sni, uint32_t unix_time, uint8_t *session, int *esp_err, uint8_t *reason);
int wifi_tls_step(uint8_t session, wifi_tls_step_t *step);
int wifi_tls_close(uint8_t session, int *esp_err);
int wifi_tls_stats(uint8_t session, wifi_tls_stats_t *stats, int *esp_err);

// The checks the calls above apply to the module's answer to request
// sequence, apart so that the host can test them. An answer must have exactly
// the size the module sends: 12 bytes for OPEN, 8 for CLOSE, 60 for STATS, and
// for STEP 16 plus the bytes it counts. Each returns 0 for the
// answer, WIFI_TLS_FOREIGN for a reply to something else, and REFUSED or
// INVALID otherwise (and AGAIN for a step), and writes its outputs as described above.
int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, uint8_t *session, int *esp_err,
                       uint8_t *reason);
int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step);
int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, int *esp_err);
int wifi_tls_take_stats(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_stats_t *stats, int *esp_err);

#ifdef TLS_SPIKE
// The spike (M2 spec section 7): connects to host:port, runs a handshake through
// the module, sends echo bytes of the payload made from seed, expects the same
// bytes back, and closes the session and the socket whatever happened. Spike
// code, not for release.
#define WIFI_TLS_SPIKE_MAX_ECHO 4096

// The payload: byte i of the one made from seed.
uint8_t wifi_tls_spike_payload(uint32_t seed, uint32_t i);

// The route's parameters, checked. host is dotted IPv4 (four decimal numbers
// 0-255), port 1-65535, sni at most WIFI_TLS_MAX_SNI bytes, verify 0 or 1
// (default 1), ca test, bundle or none (default test), echo 0-4096 (default
// 0), seed 0-4294967295 (default 0); the numbers in decimal digits only, and
// verify 1 needs a non-empty sni. An optional parameter is NULL when absent.
// Returns NULL and fills args, or text starting with the name of the first
// parameter that is not valid, and leaves args alone.
typedef struct {
    const char *host;
    uint16_t port;
    const char *sni;
    uint8_t flags;
    int echo;
    uint32_t seed;
} wifi_tls_spike_args_t;

const char *wifi_tls_spike_parse(const char *host, const char *port, const char *sni, const char *verify,
                                 const char *ca, const char *echo, const char *seed, wifi_tls_spike_args_t *args);

typedef struct {
    bool ok;
    const char *stage;   // the last stage reached: connect, open, handshake, echo, close or done
    const char *detail;  // exactly where it ended, e.g. "handshake_recv"
    char error[160];     // what ended it, "" when ok
    int code;            // the number behind error: a WIFI_TLS_* code, an errno or a state
    int esp_err;         // the module's error at that point, if any
    int state;           // the last session state seen, -1 before OPEN
    int steps;           // STEP calls, handshake and echo, resends included
    int handshake_steps;
    int resends;         // steps sent again after AGAIN
    uint32_t handshake_ms; // from OPEN to ESTABLISHED, on this side's tick
    uint32_t open_ms;      // OPEN, retries included, on this side's tick; part of handshake_ms
    uint32_t step_max_ms;  // the longest single STEP round trip, on this side's tick
    bool have_before, have_opened, have_peak, have_after;
    int stats_error;     // the last STATS call that failed, if any
    wifi_tls_stats_t before; // the module, before the socket is opened
    wifi_tls_stats_t opened; // the session, just after OPEN: its clock and where that came from
    wifi_tls_stats_t peak;   // the session, just after ESTABLISHED
    wifi_tls_stats_t after;  // the module, after the session is closed
    uint32_t unix_time;  // what OPEN carried
    const char *nios_clock; // where that came from: "sntp", "rtc" or "none"
    uint32_t tcp_out;    // ciphertext bytes sent to the server
    uint32_t tcp_in;     // ciphertext bytes received from the server
    int echo_sent;
    int echo_received;
    int early_plaintext; // plaintext bytes that came before any were sent
    bool echo_ok;
    bool session_opened;
    int close_result;    // of CLOSE, when the session was still open on the module
    bool socket_opened;
} wifi_tls_spike_result_t;

void wifi_tls_spike(const char *host, uint16_t port, const char *sni, uint8_t flags, int echo, uint32_t seed,
                    wifi_tls_spike_result_t *result);
#endif

#endif /* WIFI_TLS_H_ */
