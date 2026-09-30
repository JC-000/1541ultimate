/*
 * wifi_tls_rpc.h
 *
 * The TLS requests to the WiFi module and its answers, as they travel on the
 * UART: the Ultimate's own copy of the M3 layout (M3-SPEC v1 section 5.2).
 * The module declares the same layout in its rpc_calls.h, and each side
 * asserts the offsets it relies on, so that neither build can drift from the
 * wire without failing. Only wifi_tls.cc and its host tests include this.
 *
 * Multi-byte fields are little endian, as both CPUs are.
 */

#ifndef WIFI_TLS_RPC_H_
#define WIFI_TLS_RPC_H_

#include <stddef.h>
#include <stdint.h>
#include "rpc_calls.h" // rpc_header_t, rpc_espcmd_resp

#define NIOS_CMD_TLS_OPEN      0x30
#define NIOS_CMD_TLS_STEP      0x31
#define NIOS_CMD_TLS_CLOSE     0x32
#define NIOS_CMD_TLS_STATS     0x33
#define NIOS_CMD_TLS_CLOSE_ALL 0x34
#define NIOS_CMD_TLS_SET_CA    0x35

#define NIOS_TLS_MAX_SESSIONS  2    // the module's cap, and the size of the Nios table
#define NIOS_TLS_SNI_MAX_LEN   253
#define NIOS_TLS_STEP_IN_MAX   1536 // ct_in_len + pt_in_len per step
#define NIOS_TLS_STEP_OUT_MAX  1024 // ct_out_len + pt_out_len per step
#define NIOS_TLS_CA_MAX        1472 // one DER certificate
#define NIOS_TLS_PIN_LEN       32
#define NIOS_TLS_SPKI_LEN      32
#define NIOS_TLS_SLOT_GLOBAL   0xFF // STATS of the module as a whole, with tag 0

#define NIOS_TLS_TRUST_BUNDLE  0
#define NIOS_TLS_TRUST_CUSTOM  1
#define NIOS_TLS_TRUST_PIN     2

#define NIOS_TLS_OPT_REQUIRE_TLS13 0x01
#define NIOS_TLS_STEP_NO_READ      0x01

#define NIOS_TLS_TIME_NONE     0
#define NIOS_TLS_TIME_NIOS     1

// rpc open resp reason
#define NIOS_TLS_REASON_NO_ENTROPY   1
#define NIOS_TLS_REASON_NO_TIME      2
#define NIOS_TLS_REASON_NO_CUSTOM_CA 3

// step resp fail_reason
#define NIOS_TLS_FAIL_NONE            0
#define NIOS_TLS_FAIL_VERSION_REFUSED 1
#define NIOS_TLS_FAIL_DOWNGRADE       2
#define NIOS_TLS_FAIL_NO_EMS          3
#define NIOS_TLS_FAIL_CERT_VERIFY     4
#define NIOS_TLS_FAIL_PIN_MISMATCH    5
#define NIOS_TLS_FAIL_PEER_CLOSED     6

// set_ca resp reject
#define NIOS_TLS_REJECT_NONE          0
#define NIOS_TLS_REJECT_RSA_KEY_SHORT 1
#define NIOS_TLS_REJECT_RESERVED      2
#define NIOS_TLS_REJECT_CURVE         3
#define NIOS_TLS_REJECT_NOT_CA        4

#define NIOS_TLS_ALERT_NONE    0xFF

typedef struct {
    rpc_header_t hdr;
    uint8_t trust;       // NIOS_TLS_TRUST_*
    uint8_t sni_len;     // 0 = no name
    uint8_t slot;        // 0 .. NIOS_TLS_MAX_SESSIONS - 1, chosen by the Nios
    uint8_t time_source; // NIOS_TLS_TIME_*
    uint32_t unix_time;
    uint16_t tag;        // never 0
    uint8_t opts;        // NIOS_TLS_OPT_*
    uint8_t reserved;
    uint16_t ca_tag;     // CUSTOM: the Nios's current ca_tag, 0 otherwise
    uint16_t reserved2;
    uint8_t pin[NIOS_TLS_PIN_LEN]; // read by the module only when trust is PIN
    uint8_t sni[];
} nios_tls_open_req;

typedef struct {
    rpc_header_t hdr;
    int32_t esp_err;
    uint8_t session;
    uint8_t reason;      // NIOS_TLS_REASON_*
    uint16_t reserved;
} nios_tls_open_resp;

typedef struct {
    rpc_header_t hdr;
    uint8_t slot;
    uint8_t flags;       // NIOS_TLS_STEP_*
    uint16_t tag;
    uint16_t ct_in_len;
    uint16_t pt_in_len;
    uint8_t data[];      // ct_in, then pt_in
} nios_tls_step_req;

typedef struct {
    rpc_header_t hdr;
    int32_t esp_err;
    uint8_t state;
    uint8_t alert_in;    // NIOS_TLS_ALERT_NONE when none
    uint16_t ct_out_len;
    uint16_t pt_out_len;
    uint8_t alert_out;
    uint8_t fail_reason; // NIOS_TLS_FAIL_*
    uint32_t verify_flags;
    uint8_t data[];      // ct_out, then pt_out
} nios_tls_step_resp;

typedef struct {
    rpc_header_t hdr;
    uint8_t slot;
    uint8_t reserved;
    uint16_t tag;
} nios_tls_session_req; // CLOSE and STATS

typedef struct {
    rpc_header_t hdr;
    int32_t esp_err;
    uint16_t ct_out_len;
    uint16_t reserved;
    uint8_t data[];      // the close_notify record
} nios_tls_close_resp;

typedef struct {
    rpc_header_t hdr;
    int32_t esp_err;
    uint32_t heap_free;
    uint32_t heap_min;
    uint32_t largest_block;
    uint32_t ct_in_bytes;
    uint32_t ct_out_bytes;
    uint32_t pt_in_bytes;
    uint32_t pt_out_bytes;
    uint32_t handshake_us;
    uint16_t tls_version;
    uint16_t ciphersuite;
    uint16_t group;
    uint8_t state;
    uint8_t sessions_open;
    uint32_t stack_free;
    uint32_t esp_time;
    uint8_t time_source;
    uint8_t entropy_source;
    uint8_t ems;
    uint8_t reserved;
    uint16_t block_max_ms;
    uint16_t reserved2;
    uint8_t spki_sha256[NIOS_TLS_SPKI_LEN];
} nios_tls_stats_resp;

typedef struct {
    rpc_header_t hdr;
} nios_tls_close_all_req; // answered with rpc_espcmd_resp

typedef struct {
    rpc_header_t hdr;
    uint16_t der_len;
    uint16_t ca_tag;
    uint8_t der[];
} nios_tls_set_ca_req;

typedef struct {
    rpc_header_t hdr;
    int32_t esp_err;
    uint8_t reject;      // NIOS_TLS_REJECT_*
    uint8_t reserved[3];
} nios_tls_set_ca_resp;

// M3-SPEC v1 section 5.2, byte for byte.
static_assert(sizeof(rpc_header_t) == 4, "rpc_header_t");
static_assert(sizeof(rpc_espcmd_resp) == 8, "rpc_espcmd_resp");
static_assert(offsetof(nios_tls_open_req, trust) == 4, "open.trust");
static_assert(offsetof(nios_tls_open_req, sni_len) == 5, "open.sni_len");
static_assert(offsetof(nios_tls_open_req, slot) == 6, "open.slot");
static_assert(offsetof(nios_tls_open_req, time_source) == 7, "open.time_source");
static_assert(offsetof(nios_tls_open_req, unix_time) == 8, "open.unix_time");
static_assert(offsetof(nios_tls_open_req, tag) == 12, "open.tag");
static_assert(offsetof(nios_tls_open_req, opts) == 14, "open.opts");
static_assert(offsetof(nios_tls_open_req, reserved) == 15, "open.reserved");
static_assert(offsetof(nios_tls_open_req, ca_tag) == 16, "open.ca_tag");
static_assert(offsetof(nios_tls_open_req, reserved2) == 18, "open.reserved2");
static_assert(offsetof(nios_tls_open_req, pin) == 20, "open.pin");
static_assert(offsetof(nios_tls_open_req, sni) == 52, "open.sni");
static_assert(sizeof(nios_tls_open_req) == 52, "open size");
static_assert(offsetof(nios_tls_open_resp, esp_err) == 4, "open resp.esp_err");
static_assert(offsetof(nios_tls_open_resp, session) == 8, "open resp.session");
static_assert(offsetof(nios_tls_open_resp, reason) == 9, "open resp.reason");
static_assert(sizeof(nios_tls_open_resp) == 12, "open resp size");
static_assert(offsetof(nios_tls_step_req, slot) == 4, "step.slot");
static_assert(offsetof(nios_tls_step_req, flags) == 5, "step.flags");
static_assert(offsetof(nios_tls_step_req, tag) == 6, "step.tag");
static_assert(offsetof(nios_tls_step_req, ct_in_len) == 8, "step.ct_in_len");
static_assert(offsetof(nios_tls_step_req, pt_in_len) == 10, "step.pt_in_len");
static_assert(offsetof(nios_tls_step_req, data) == 12, "step.data");
static_assert(sizeof(nios_tls_step_req) == 12, "step size");
static_assert(offsetof(nios_tls_step_resp, esp_err) == 4, "step resp.esp_err");
static_assert(offsetof(nios_tls_step_resp, state) == 8, "step resp.state");
static_assert(offsetof(nios_tls_step_resp, alert_in) == 9, "step resp.alert_in");
static_assert(offsetof(nios_tls_step_resp, ct_out_len) == 10, "step resp.ct_out_len");
static_assert(offsetof(nios_tls_step_resp, pt_out_len) == 12, "step resp.pt_out_len");
static_assert(offsetof(nios_tls_step_resp, alert_out) == 14, "step resp.alert_out");
static_assert(offsetof(nios_tls_step_resp, fail_reason) == 15, "step resp.fail_reason");
static_assert(offsetof(nios_tls_step_resp, verify_flags) == 16, "step resp.verify_flags");
static_assert(offsetof(nios_tls_step_resp, data) == 20, "step resp.data");
static_assert(sizeof(nios_tls_step_resp) == 20, "step resp size");
static_assert(offsetof(nios_tls_session_req, slot) == 4, "session.slot");
static_assert(offsetof(nios_tls_session_req, reserved) == 5, "session.reserved");
static_assert(offsetof(nios_tls_session_req, tag) == 6, "session.tag");
static_assert(sizeof(nios_tls_session_req) == 8, "session size");
static_assert(offsetof(nios_tls_close_resp, esp_err) == 4, "close resp.esp_err");
static_assert(offsetof(nios_tls_close_resp, ct_out_len) == 8, "close resp.ct_out_len");
static_assert(offsetof(nios_tls_close_resp, reserved) == 10, "close resp.reserved");
static_assert(offsetof(nios_tls_close_resp, data) == 12, "close resp.data");
static_assert(sizeof(nios_tls_close_resp) == 12, "close resp size");
static_assert(offsetof(nios_tls_stats_resp, esp_err) == 4, "stats.esp_err");
static_assert(offsetof(nios_tls_stats_resp, handshake_us) == 36, "stats.handshake_us");
static_assert(offsetof(nios_tls_stats_resp, tls_version) == 40, "stats.tls_version");
static_assert(offsetof(nios_tls_stats_resp, ciphersuite) == 42, "stats.ciphersuite");
static_assert(offsetof(nios_tls_stats_resp, group) == 44, "stats.group");
static_assert(offsetof(nios_tls_stats_resp, state) == 46, "stats.state");
static_assert(offsetof(nios_tls_stats_resp, sessions_open) == 47, "stats.sessions_open");
static_assert(offsetof(nios_tls_stats_resp, stack_free) == 48, "stats.stack_free");
static_assert(offsetof(nios_tls_stats_resp, esp_time) == 52, "stats.esp_time");
static_assert(offsetof(nios_tls_stats_resp, time_source) == 56, "stats.time_source");
static_assert(offsetof(nios_tls_stats_resp, entropy_source) == 57, "stats.entropy_source");
static_assert(offsetof(nios_tls_stats_resp, ems) == 58, "stats.ems");
static_assert(offsetof(nios_tls_stats_resp, reserved) == 59, "stats.reserved");
static_assert(offsetof(nios_tls_stats_resp, block_max_ms) == 60, "stats.block_max_ms");
static_assert(offsetof(nios_tls_stats_resp, reserved2) == 62, "stats.reserved2");
static_assert(offsetof(nios_tls_stats_resp, spki_sha256) == 64, "stats.spki_sha256");
static_assert(sizeof(nios_tls_stats_resp) == 96, "stats size");
static_assert(sizeof(nios_tls_close_all_req) == 4, "close_all size");
static_assert(offsetof(nios_tls_set_ca_req, der_len) == 4, "set_ca.der_len");
static_assert(offsetof(nios_tls_set_ca_req, ca_tag) == 6, "set_ca.ca_tag");
static_assert(offsetof(nios_tls_set_ca_req, der) == 8, "set_ca.der");
static_assert(sizeof(nios_tls_set_ca_req) == 8, "set_ca size");
static_assert(offsetof(nios_tls_set_ca_resp, esp_err) == 4, "set_ca resp.esp_err");
static_assert(offsetof(nios_tls_set_ca_resp, reject) == 8, "set_ca resp.reject");
static_assert(sizeof(nios_tls_set_ca_resp) == 12, "set_ca resp size");

// The values both layouts share with the module's own header.
static_assert(NIOS_TLS_MAX_SESSIONS == TLS_MAX_SESSIONS, "session caps differ");
static_assert(NIOS_TLS_SNI_MAX_LEN == TLS_SNI_MAX_LEN, "name lengths differ");
static_assert(NIOS_TLS_STEP_IN_MAX == TLS_STEP_IN_MAX, "step sizes differ");
static_assert(NIOS_TLS_STEP_OUT_MAX == TLS_STEP_OUT_MAX, "step sizes differ");
static_assert(NIOS_CMD_TLS_OPEN == CMD_TLS_OPEN, "commands differ");
static_assert(NIOS_CMD_TLS_STEP == CMD_TLS_STEP, "commands differ");
static_assert(NIOS_CMD_TLS_CLOSE == CMD_TLS_CLOSE, "commands differ");
static_assert(NIOS_CMD_TLS_STATS == CMD_TLS_STATS, "commands differ");

#endif /* WIFI_TLS_RPC_H_ */
