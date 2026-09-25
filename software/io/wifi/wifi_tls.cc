/*
 * wifi_tls.cc
 *
 * The TLS calls to the WiFi module: what goes into each request and what is
 * taken from each answer. The waiting is wifi_dedicated_call's. Free of
 * FreeRTOS calls, so that the checks can be tested on the host.
 */

#include <stddef.h>
#include <string.h>
#include "rpc_calls.h"
extern "C" {
    #include "cmd_buffer.h"
}
#include "wifi_dedicated.h"
#include "wifi_tls.h"

// The layout the module sends and this code reads, as rpc_dispatch.c asserts it
// on the module's side. Checked here so that the firmware build itself fails
// if it ever changes.
static_assert(sizeof(rpc_espcmd_resp) == 8, "rpc_espcmd_resp size");
static_assert(offsetof(rpc_espcmd_resp, esp_err) == 4, "rpc_espcmd_resp.esp_err");
static_assert(sizeof(rpc_tls_open_req) == 12, "rpc_tls_open_req size");
static_assert(offsetof(rpc_tls_open_req, flags) == 4, "rpc_tls_open_req.flags");
static_assert(offsetof(rpc_tls_open_req, sni_len) == 5, "rpc_tls_open_req.sni_len");
static_assert(offsetof(rpc_tls_open_req, unix_time) == 8, "rpc_tls_open_req.unix_time");
static_assert(offsetof(rpc_tls_open_req, sni) == 12, "rpc_tls_open_req.sni");
static_assert(sizeof(rpc_tls_open_resp) == 12, "rpc_tls_open_resp size");
static_assert(offsetof(rpc_tls_open_resp, esp_err) == 4, "rpc_tls_open_resp.esp_err");
static_assert(offsetof(rpc_tls_open_resp, session) == 8, "rpc_tls_open_resp.session");
static_assert(offsetof(rpc_tls_open_resp, reason) == 9, "rpc_tls_open_resp.reason");
static_assert(sizeof(rpc_tls_step_req) == 10, "rpc_tls_step_req size");
static_assert(offsetof(rpc_tls_step_req, session) == 4, "rpc_tls_step_req.session");
static_assert(offsetof(rpc_tls_step_req, ct_in_len) == 6, "rpc_tls_step_req.ct_in_len");
static_assert(offsetof(rpc_tls_step_req, pt_in_len) == 8, "rpc_tls_step_req.pt_in_len");
static_assert(offsetof(rpc_tls_step_req, data) == 10, "rpc_tls_step_req.data");
static_assert(sizeof(rpc_tls_step_resp) == 16, "rpc_tls_step_resp size");
static_assert(offsetof(rpc_tls_step_resp, esp_err) == 4, "rpc_tls_step_resp.esp_err");
static_assert(offsetof(rpc_tls_step_resp, state) == 8, "rpc_tls_step_resp.state");
static_assert(offsetof(rpc_tls_step_resp, ct_out_len) == 10, "rpc_tls_step_resp.ct_out_len");
static_assert(offsetof(rpc_tls_step_resp, pt_out_len) == 12, "rpc_tls_step_resp.pt_out_len");
static_assert(offsetof(rpc_tls_step_resp, data) == 16, "rpc_tls_step_resp.data");
static_assert(sizeof(rpc_tls_session_req) == 6, "rpc_tls_session_req size");
static_assert(offsetof(rpc_tls_session_req, session) == 4, "rpc_tls_session_req.session");
static_assert(sizeof(rpc_tls_stats_resp) == 60, "rpc_tls_stats_resp size");
static_assert(offsetof(rpc_tls_stats_resp, esp_err) == 4, "rpc_tls_stats_resp.esp_err");
static_assert(offsetof(rpc_tls_stats_resp, heap_free) == 8, "rpc_tls_stats_resp.heap_free");
static_assert(offsetof(rpc_tls_stats_resp, heap_min) == 12, "rpc_tls_stats_resp.heap_min");
static_assert(offsetof(rpc_tls_stats_resp, largest_block) == 16, "rpc_tls_stats_resp.largest_block");
static_assert(offsetof(rpc_tls_stats_resp, ct_in_bytes) == 20, "rpc_tls_stats_resp.ct_in_bytes");
static_assert(offsetof(rpc_tls_stats_resp, ct_out_bytes) == 24, "rpc_tls_stats_resp.ct_out_bytes");
static_assert(offsetof(rpc_tls_stats_resp, pt_in_bytes) == 28, "rpc_tls_stats_resp.pt_in_bytes");
static_assert(offsetof(rpc_tls_stats_resp, pt_out_bytes) == 32, "rpc_tls_stats_resp.pt_out_bytes");
static_assert(offsetof(rpc_tls_stats_resp, handshake_us) == 36, "rpc_tls_stats_resp.handshake_us");
static_assert(offsetof(rpc_tls_stats_resp, tls_version) == 40, "rpc_tls_stats_resp.tls_version");
static_assert(offsetof(rpc_tls_stats_resp, ciphersuite) == 42, "rpc_tls_stats_resp.ciphersuite");
static_assert(offsetof(rpc_tls_stats_resp, group) == 44, "rpc_tls_stats_resp.group");
static_assert(offsetof(rpc_tls_stats_resp, state) == 46, "rpc_tls_stats_resp.state");
static_assert(offsetof(rpc_tls_stats_resp, sessions_open) == 47, "rpc_tls_stats_resp.sessions_open");
static_assert(offsetof(rpc_tls_stats_resp, stack_free) == 48, "rpc_tls_stats_resp.stack_free");
static_assert(offsetof(rpc_tls_stats_resp, esp_time) == 52, "rpc_tls_stats_resp.esp_time");
static_assert(offsetof(rpc_tls_stats_resp, time_source) == 56, "rpc_tls_stats_resp.time_source");

// A full step, either way, fits one buffer, and so does the longest OPEN.
static_assert(sizeof(rpc_tls_open_req) + TLS_SNI_MAX_LEN <= CMD_BUF_SIZE, "largest CMD_TLS_OPEN request");
static_assert(sizeof(rpc_tls_step_req) + TLS_STEP_IN_MAX <= CMD_BUF_SIZE, "largest CMD_TLS_STEP request");
static_assert(sizeof(rpc_tls_step_resp) + TLS_STEP_OUT_MAX <= CMD_BUF_SIZE, "largest CMD_TLS_STEP reply");

// What wifi_tls.h repeats.
static_assert(WIFI_TLS_FLAG_VERIFY == TLS_OPEN_VERIFY, "flags differ");
static_assert(WIFI_TLS_FLAG_CA_BUNDLE == TLS_OPEN_CA_BUNDLE, "flags differ");
static_assert(WIFI_TLS_FLAG_TEST_CA == TLS_OPEN_CA_TEST, "flags differ");
static_assert(WIFI_TLS_SESSION_GLOBAL == TLS_SESSION_GLOBAL, "sessions differ");
static_assert(WIFI_TLS_MAX_SNI == TLS_SNI_MAX_LEN, "name lengths differ");
static_assert(WIFI_TLS_STEP_MAX_IN == TLS_STEP_IN_MAX, "step sizes differ");
static_assert(WIFI_TLS_REASON_NO_ENTROPY == TLS_OPEN_REASON_NO_ENTROPY, "reasons differ");
static_assert(WIFI_TLS_REASON_NO_TIME == TLS_OPEN_REASON_NO_TIME, "reasons differ");
static_assert(WIFI_TLS_TIME_NONE == TLS_TIME_NONE, "time sources differ");
static_assert(WIFI_TLS_TIME_NIOS == TLS_TIME_NIOS, "time sources differ");
static_assert(WIFI_TLS_TIME_SNTP == TLS_TIME_SNTP, "time sources differ");
static_assert(WIFI_TLS_HANDSHAKING == TLS_STATE_HANDSHAKING, "states differ");
static_assert(WIFI_TLS_ESTABLISHED == TLS_STATE_ESTABLISHED, "states differ");
static_assert(WIFI_TLS_CLOSED == TLS_STATE_CLOSED, "states differ");
static_assert(WIFI_TLS_FAILED == TLS_STATE_FAILED, "states differ");
static_assert(WIFI_TLS_BUSY == DEDICATED_BUSY, "codes differ");
static_assert(WIFI_TLS_NO_MODULE == DEDICATED_NO_MODULE, "codes differ");
static_assert(WIFI_TLS_FOREIGN == DEDICATED_FOREIGN, "codes differ");
static_assert(WIFI_TLS_UNSENT == DEDICATED_UNSENT, "codes differ");

// ESP_ERR_NO_MEM (esp_err.h), which a STEP answers when it had no room for the
// input.
#define ESP_ERR_NO_MEM_VALUE 0x101

// How long each call waits for its answer. A step can carry a whole flight of
// the handshake, and so the key exchange and the chain verification, which
// block the module's dispatcher for up to about a second. The first OPEN seeds
// PSA's generator and every OPEN parses its trust anchors. A close can find the
// module still busy with a step whose answer came too late.
#define OPEN_TIMEOUT_MS  5000
#define STEP_TIMEOUT_MS  5000
#define CLOSE_TIMEOUT_MS 5000
#define STATS_TIMEOUT_MS 1000

static bool is_answer(const uint8_t *reply, int size, uint8_t command, uint16_t sequence)
{
    const rpc_header_t *hdr = (const rpc_header_t *)reply;
    return (size >= (int)sizeof(rpc_header_t)) && (hdr->command == command) && (hdr->sequence == sequence);
}

int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, uint8_t *session, int *esp_err,
                       uint8_t *reason)
{
    const rpc_tls_open_resp *result = (const rpc_tls_open_resp *)reply;
    if (!is_answer(reply, size, CMD_TLS_OPEN, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (size != (int)sizeof(rpc_tls_open_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        *reason = result->reason;
        return WIFI_TLS_REFUSED;
    }
    if (result->session == TLS_SESSION_GLOBAL) {
        return WIFI_TLS_INVALID;
    }
    *session = result->session;
    return 0;
}

int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step)
{
    const rpc_tls_step_resp *result = (const rpc_tls_step_resp *)reply;
    const int header = offsetof(rpc_tls_step_resp, data);
    if (!is_answer(reply, size, CMD_TLS_STEP, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    // Exactly the header and the bytes it counts, no more and no less.
    if ((size < header) || (size != header + result->ct_out_len + result->pt_out_len)) {
        return WIFI_TLS_INVALID;
    }
    bool has_state = result->state <= TLS_STATE_FAILED;
    bool failed = has_state && (result->state == TLS_STATE_FAILED);
    // Input refused for want of room, output all the same. In a live session
    // the input goes again. Once the peer has closed, the refusal no longer
    // matters: the output, the last plaintext included, is taken and the
    // session reported CLOSED.
    bool no_mem = has_state && (result->esp_err == ESP_ERR_NO_MEM_VALUE);
    bool again = no_mem && ((result->state == TLS_STATE_HANDSHAKING) || (result->state == TLS_STATE_ESTABLISHED));
    bool closed = no_mem && (result->state == TLS_STATE_CLOSED);
    if ((result->esp_err != 0) && !failed && !again && !closed) {
        step->esp_err = result->esp_err;
        if (has_state) {
            step->state = result->state;
        }
        return WIFI_TLS_REFUSED;
    }
    if (!has_state) {
        return WIFI_TLS_INVALID;
    }
    uint16_t ct = result->ct_out_len;
    uint16_t pt = result->pt_out_len;
    if ((ct > step->ct_out_room) || (pt > step->pt_out_room)) {
        return WIFI_TLS_INVALID;
    }
    // Plaintext only from a session that has finished its handshake. Records
    // read before a failure were authentic, but they end a session that failed,
    // and are withheld.
    if (failed) {
        pt = 0;
    } else if ((pt != 0) && (result->state != TLS_STATE_ESTABLISHED) && (result->state != TLS_STATE_CLOSED)) {
        return WIFI_TLS_INVALID;
    }
    memcpy(step->ct_out, result->data, ct);
    memcpy(step->pt_out, result->data + ct, pt);
    step->ct_out_len = ct;
    step->pt_out_len = pt;
    step->state = result->state;
    step->esp_err = result->esp_err;
    return again ? WIFI_TLS_AGAIN : 0;
}

int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, int *esp_err)
{
    const rpc_espcmd_resp *result = (const rpc_espcmd_resp *)reply;
    if (!is_answer(reply, size, CMD_TLS_CLOSE, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (size != (int)sizeof(rpc_espcmd_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        return WIFI_TLS_REFUSED;
    }
    return 0;
}

int wifi_tls_take_stats(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_stats_t *stats, int *esp_err)
{
    const rpc_tls_stats_resp *result = (const rpc_tls_stats_resp *)reply;
    if (!is_answer(reply, size, CMD_TLS_STATS, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (size != (int)sizeof(rpc_tls_stats_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        return WIFI_TLS_REFUSED;
    }
    stats->heap_free = result->heap_free;
    stats->heap_min_ever = result->heap_min;
    stats->largest_block = result->largest_block;
    stats->ct_in_bytes = result->ct_in_bytes;
    stats->ct_out_bytes = result->ct_out_bytes;
    stats->pt_in_bytes = result->pt_in_bytes;
    stats->pt_out_bytes = result->pt_out_bytes;
    stats->handshake_us = result->handshake_us;
    stats->tls_version = result->tls_version;
    stats->ciphersuite = result->ciphersuite;
    stats->group = result->group;
    stats->state = result->state;
    stats->sessions_open = result->sessions_open;
    stats->stack_free = result->stack_free;
    stats->esp_time = result->esp_time;
    stats->time_source = result->time_source;
    return 0;
}

typedef struct {
    uint8_t flags;
    const char *sni;
    uint8_t sni_len;
    uint32_t unix_time;
    uint8_t *session;
    int *esp_err;
    uint8_t *reason;
} open_call_t;

static int fill_open(uint8_t *request, void *context)
{
    open_call_t *c = (open_call_t *)context;
    rpc_tls_open_req *args = (rpc_tls_open_req *)request;
    args->flags = c->flags;
    args->sni_len = c->sni_len;
    args->reserved = 0;
    args->unix_time = c->unix_time;
    memcpy(args->sni, c->sni, c->sni_len);
    return offsetof(rpc_tls_open_req, sni) + c->sni_len;
}

static int take_open(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    open_call_t *c = (open_call_t *)context;
    return wifi_tls_take_open(reply, size, sequence, c->session, c->esp_err, c->reason);
}

int wifi_tls_open(uint8_t flags, const char *sni, uint32_t unix_time, uint8_t *session, int *esp_err, uint8_t *reason)
{
    *esp_err = 0;
    *reason = 0;
    size_t sni_len = sni ? strlen(sni) : 0;
    if (sni_len > WIFI_TLS_MAX_SNI) {
        return WIFI_TLS_TOO_LONG;
    }
    open_call_t args = { flags, sni, (uint8_t)sni_len, unix_time, session, esp_err, reason };
    const dedicated_call_t call = { "TLS Open", CMD_TLS_OPEN, OPEN_TIMEOUT_MS, fill_open, take_open, &args };
    return wifi_dedicated_call(&call);
}

typedef struct {
    uint8_t session;
    wifi_tls_step_t *step;
} step_call_t;

static int fill_step(uint8_t *request, void *context)
{
    step_call_t *c = (step_call_t *)context;
    wifi_tls_step_t *step = c->step;
    rpc_tls_step_req *args = (rpc_tls_step_req *)request;
    args->session = c->session;
    args->reserved = 0;
    args->ct_in_len = step->ct_in_len;
    args->pt_in_len = step->pt_in_len;
    memcpy(args->data, step->ct_in, step->ct_in_len);
    memcpy(args->data + step->ct_in_len, step->pt_in, step->pt_in_len);
    return offsetof(rpc_tls_step_req, data) + step->ct_in_len + step->pt_in_len;
}

static int take_step(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    return wifi_tls_take_step(reply, size, sequence, ((step_call_t *)context)->step);
}

int wifi_tls_step(uint8_t session, wifi_tls_step_t *step)
{
    step->ct_out_len = 0;
    step->pt_out_len = 0;
    step->state = WIFI_TLS_UNKNOWN;
    step->esp_err = 0;
    if ((int)step->ct_in_len + step->pt_in_len > WIFI_TLS_STEP_MAX_IN) {
        return WIFI_TLS_TOO_LONG;
    }
    step_call_t args = { session, step };
    const dedicated_call_t call = { "TLS Step", CMD_TLS_STEP, STEP_TIMEOUT_MS, fill_step, take_step, &args };
    return wifi_dedicated_call(&call);
}

typedef struct {
    uint8_t session;
    wifi_tls_stats_t *stats;
    int *esp_err;
} session_call_t;

// CLOSE and STATS carry the same argument.
static int fill_session(uint8_t *request, void *context)
{
    rpc_tls_session_req *args = (rpc_tls_session_req *)request;
    args->session = ((session_call_t *)context)->session;
    args->reserved = 0;
    return sizeof(rpc_tls_session_req);
}

static int take_close(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    return wifi_tls_take_close(reply, size, sequence, ((session_call_t *)context)->esp_err);
}

int wifi_tls_close(uint8_t session, int *esp_err)
{
    *esp_err = 0;
    session_call_t args = { session, NULL, esp_err };
    const dedicated_call_t call = { "TLS Close", CMD_TLS_CLOSE, CLOSE_TIMEOUT_MS, fill_session, take_close, &args };
    return wifi_dedicated_call(&call);
}

static int take_stats(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    session_call_t *c = (session_call_t *)context;
    return wifi_tls_take_stats(reply, size, sequence, c->stats, c->esp_err);
}

int wifi_tls_stats(uint8_t session, wifi_tls_stats_t *stats, int *esp_err)
{
    *esp_err = 0;
    session_call_t args = { session, stats, esp_err };
    const dedicated_call_t call = { "TLS Stats", CMD_TLS_STATS, STATS_TIMEOUT_MS, fill_session, take_stats, &args };
    return wifi_dedicated_call(&call);
}
