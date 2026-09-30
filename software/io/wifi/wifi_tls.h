/*
 * wifi_tls.h
 *
 * TLS sessions that run on the WiFi module (esp-tls M3). The module
 * holds the keys and runs the protocol; this side carries the ciphertext
 * between a socket and the module, one step at a time, and the module never
 * speaks unasked. U64 only.
 *
 * Kept apart from wifi_cmd.h, like wifi_random.h, so that its users do not see
 * the module's RPC definitions; wifi_tls.cc asserts that the values repeated
 * here match the wire layout in wifi_tls_rpc.h.
 */

#ifndef WIFI_TLS_H_
#define WIFI_TLS_H_

#include <stdint.h>

#define WIFI_TLS_MAX_SESSIONS   2    // the module's cap
#define WIFI_TLS_MAX_SNI        253
#define WIFI_TLS_STEP_MAX_IN    1536 // ct_in_len + pt_in_len in one step
#define WIFI_TLS_STEP_MAX_OUT   1024 // ct_out_len + pt_out_len in one step
#define WIFI_TLS_CA_MAX         1472 // one DER certificate for SET_CA
#define WIFI_TLS_PIN_LEN        32
#define WIFI_TLS_SLOT_GLOBAL    0xFF // for wifi_tls_stats: the module as a whole, with tag 0

#define WIFI_TLS_TRUST_BUNDLE   0
#define WIFI_TLS_TRUST_CUSTOM   1
#define WIFI_TLS_TRUST_PIN      2

#define WIFI_TLS_OPT_REQUIRE_TLS13 0x01 // offer TLS 1.3 only
#define WIFI_TLS_STEP_NO_READ      0x01 // the module takes no plaintext out of the session in this step

// Why an OPEN was refused.
#define WIFI_TLS_REASON_NO_ENTROPY   1 // the radio has not started, so there is no seed
#define WIFI_TLS_REASON_NO_TIME      2 // BUNDLE or CUSTOM, and neither side has a trustworthy clock
#define WIFI_TLS_REASON_NO_CUSTOM_CA 3 // CUSTOM, and the module holds no CA under the given ca_tag

// Where the time in an OPEN came from.
#define WIFI_TLS_TIME_NONE 0
#define WIFI_TLS_TIME_NIOS 1 // SNTP on this side

#define WIFI_TLS_HANDSHAKING    0
#define WIFI_TLS_ESTABLISHED    1
#define WIFI_TLS_CLOSED         2
#define WIFI_TLS_FAILED         3 // esp_err holds the mbedTLS error, fail_reason says more
#define WIFI_TLS_UNKNOWN        0xFF // the answer did not say

// Why a step FAILED (M3-SPEC 5.2), besides esp_err.
#define WIFI_TLS_FAIL_NONE            0 // generic: esp_err has the mbedTLS code, alert_in any alert
#define WIFI_TLS_FAIL_VERSION_REFUSED 1 // the version chosen is in verify_flags' low 16 bits
#define WIFI_TLS_FAIL_DOWNGRADE       2
#define WIFI_TLS_FAIL_NO_EMS          3
#define WIFI_TLS_FAIL_CERT_VERIFY     4 // verify_flags is the final verify result
#define WIFI_TLS_FAIL_PIN_MISMATCH    5
#define WIFI_TLS_FAIL_PEER_CLOSED     6

#define WIFI_TLS_ALERT_NONE     0xFF

// Why SET_CA refused a certificate that parsed.
#define WIFI_TLS_REJECT_NONE          0
#define WIFI_TLS_REJECT_RSA_KEY_SHORT 1
#define WIFI_TLS_REJECT_CURVE         3
#define WIFI_TLS_REJECT_NOT_CA        4

// esp_err values the callers tell apart (esp_err.h).
#define WIFI_TLS_ESP_FAIL          (-1)
#define WIFI_TLS_ESP_NO_MEM        0x101
#define WIFI_TLS_ESP_INVALID_ARG   0x102
#define WIFI_TLS_ESP_INVALID_STATE 0x103
#define WIFI_TLS_ESP_NOT_FOUND     0x105
#define WIFI_TLS_ESP_NOT_SUPPORTED 0x106

// What the calls below return besides 0.
#define WIFI_TLS_BUSY      1 // sent, but no answer in time, or cancelled; the module may still act on it
#define WIFI_TLS_REFUSED   2 // the module answered with an error, which is in esp_err
#define WIFI_TLS_INVALID   3 // the answer is not a well formed reply
#define WIFI_TLS_NO_MODULE 4 // the module application is not running; nothing was sent
#define WIFI_TLS_FOREIGN   5 // (from the checks only) not the answer to this request
#define WIFI_TLS_UNSENT    6 // another request was outstanding, or no buffer; nothing was sent
#define WIFI_TLS_TOO_LONG  7 // the request does not fit; nothing was sent
#define WIFI_TLS_AGAIN     8 // STEP only: the module had no room and did not take the input, but its
                             // output is handed over as for 0; send the same input again

// Polled between the slices of a wait; true ends the wait with BUSY. NULL
// for no cancelling.
typedef struct {
    bool (*cancelled)(void *context);
    void *context;
} wifi_tls_cancel_t;

typedef struct {
    uint8_t trust;        // WIFI_TLS_TRUST_*
    uint8_t slot;         // 0 .. WIFI_TLS_MAX_SESSIONS - 1
    uint16_t tag;         // never 0; names the session together with slot
    uint8_t opts;         // WIFI_TLS_OPT_*
    uint8_t time_source;  // WIFI_TLS_TIME_*
    uint32_t unix_time;   // UTC seconds, 0 without a time source
    uint16_t ca_tag;      // CUSTOM: the CA the module must hold; 0 otherwise
    const uint8_t *pin;   // PIN: WIFI_TLS_PIN_LEN bytes; NULL otherwise (sent as zeros)
    const char *sni;      // the server name, or NULL for none
    uint8_t sni_len;
} wifi_tls_open_t;

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
    uint8_t state;
    uint8_t sessions_open;
    uint32_t stack_free;
    uint32_t esp_time;
    uint8_t time_source;
    uint8_t entropy_source; // 0: no live entropy source
    uint8_t ems;          // 1: extended master secret in use
    uint16_t block_max_ms; // the longest the module's dispatcher was blocked since boot
    uint8_t spki_sha256[32]; // of the leaf's SubjectPublicKeyInfo, digest order
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
// FAILED, the mbedTLS error in esp_err and the module's reason in fail_reason,
// alert_in and verify_flags, and ct_out may hold the alert for the server. The
// module has then freed the session, as it has after CLOSED. REFUSED is for an
// error in any other state: ESP_ERR_NOT_FOUND means the module holds no session
// under this slot and tag. Nothing is written to ct_out or pt_out unless the call
// returns 0 or AGAIN, and plaintext only ever comes from a session that is
// ESTABLISHED or has just been CLOSED; what a FAILED answer carries is withheld.
// With NO_READ in flags a step that hands out plaintext is not well formed.
typedef struct {
    uint8_t flags;        // WIFI_TLS_STEP_*
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
    uint8_t alert_in;     // WIFI_TLS_ALERT_NONE when none
    uint8_t alert_out;
    uint8_t fail_reason;  // WIFI_TLS_FAIL_*
    uint32_t verify_flags;
} wifi_tls_step_t;

// Each returns 0 or one of the codes above, after at most timeout_ms, or
// earlier with BUSY when cancel says so. esp_err, where there is one, is set to
// 0 first and to the module's error when it answered with one. reason and
// reject are set to 0 first, and to what the module says when it refused.
int wifi_tls_open(const wifi_tls_open_t *open, uint32_t timeout_ms, const wifi_tls_cancel_t *cancel, int *esp_err,
                  uint8_t *reason);
int wifi_tls_step(uint8_t slot, uint16_t tag, wifi_tls_step_t *step, uint32_t timeout_ms,
                  const wifi_tls_cancel_t *cancel);
// ct_out receives the close_notify record, at most room bytes; *ct_out_len is 0 without one.
int wifi_tls_close(uint8_t slot, uint16_t tag, uint8_t *ct_out, uint16_t room, uint16_t *ct_out_len, int *esp_err,
                   uint32_t timeout_ms, const wifi_tls_cancel_t *cancel);
int wifi_tls_stats(uint8_t slot, uint16_t tag, wifi_tls_stats_t *stats, int *esp_err, uint32_t timeout_ms,
                   const wifi_tls_cancel_t *cancel);
int wifi_tls_close_all(int *esp_err, uint32_t timeout_ms);
int wifi_tls_set_ca(const uint8_t *der, uint16_t der_len, uint16_t ca_tag, int *esp_err, uint8_t *reject,
                    uint32_t timeout_ms, const wifi_tls_cancel_t *cancel);

// The checks the calls above apply to the module's answer to request
// sequence, apart so that the host can test them. An answer must have exactly
// the size the module sends: 12 bytes for OPEN, 12 plus the record for CLOSE,
// 96 for STATS, 8 for CLOSE_ALL, 12 for SET_CA, and for STEP 20 plus the bytes it
// counts. A refusal may also come as the 8 bytes of a bare rpc_espcmd_resp,
// which is how a module without TLS answers (ESP_ERR_NOT_SUPPORTED). Each returns
// 0 for the answer, WIFI_TLS_FOREIGN for a reply to something else, and REFUSED
// or INVALID otherwise (and AGAIN for a step), and writes its outputs as
// described above.
int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, int *esp_err, uint8_t *reason);
int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step);
int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, uint8_t *ct_out, uint16_t room,
                        uint16_t *ct_out_len, int *esp_err);
int wifi_tls_take_stats(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_stats_t *stats, int *esp_err);
int wifi_tls_take_close_all(const uint8_t *reply, int size, uint16_t sequence, int *esp_err);
int wifi_tls_take_set_ca(const uint8_t *reply, int size, uint16_t sequence, int *esp_err, uint8_t *reject);

// The UART buffer generation, which changes when the module restarts: every
// session it held is then gone. In wifi_dedicated.cc.
uint32_t wifi_tls_generation(void);

// Whether TLS calls can be sent at all (the module application runs and WiFi
// is not disabled), and the version the module reported. In wifi.cc.
bool wifi_tls_module_available(void);
void wifi_tls_module_version(uint16_t *major, uint16_t *minor);

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
