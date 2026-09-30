/*
 * wifi_tls.cc
 *
 * The TLS calls to the WiFi module: what goes into each request and what is
 * taken from each answer. The waiting is wifi_dedicated_call's. Free of
 * FreeRTOS calls, so that the checks can be tested on the host.
 */

#include <stddef.h>
#include <string.h>
#include "wifi_tls_rpc.h"
extern "C" {
    #include "cmd_buffer.h"
}
#include "wifi_dedicated.h"
#include "wifi_tls.h"

// A full step, either way, fits one buffer, and so do the longest OPEN and SET_CA.
static_assert(sizeof(nios_tls_open_req) + NIOS_TLS_SNI_MAX_LEN <= CMD_BUF_SIZE, "largest CMD_TLS_OPEN request");
static_assert(sizeof(nios_tls_step_req) + NIOS_TLS_STEP_IN_MAX <= CMD_BUF_SIZE, "largest CMD_TLS_STEP request");
static_assert(sizeof(nios_tls_step_resp) + NIOS_TLS_STEP_OUT_MAX <= CMD_BUF_SIZE, "largest CMD_TLS_STEP reply");
static_assert(sizeof(nios_tls_set_ca_req) + NIOS_TLS_CA_MAX <= CMD_BUF_SIZE, "largest CMD_TLS_SET_CA request");

// What wifi_tls.h repeats.
static_assert(WIFI_TLS_MAX_SESSIONS == NIOS_TLS_MAX_SESSIONS, "session caps differ");
static_assert(WIFI_TLS_MAX_SNI == NIOS_TLS_SNI_MAX_LEN, "name lengths differ");
static_assert(WIFI_TLS_STEP_MAX_IN == NIOS_TLS_STEP_IN_MAX, "step sizes differ");
static_assert(WIFI_TLS_STEP_MAX_OUT == NIOS_TLS_STEP_OUT_MAX, "step sizes differ");
static_assert(WIFI_TLS_CA_MAX == NIOS_TLS_CA_MAX, "CA sizes differ");
static_assert(WIFI_TLS_PIN_LEN == NIOS_TLS_PIN_LEN, "pin lengths differ");
static_assert(WIFI_TLS_SLOT_GLOBAL == NIOS_TLS_SLOT_GLOBAL, "slots differ");
static_assert(WIFI_TLS_TRUST_BUNDLE == NIOS_TLS_TRUST_BUNDLE, "trust modes differ");
static_assert(WIFI_TLS_TRUST_CUSTOM == NIOS_TLS_TRUST_CUSTOM, "trust modes differ");
static_assert(WIFI_TLS_TRUST_PIN == NIOS_TLS_TRUST_PIN, "trust modes differ");
static_assert(WIFI_TLS_OPT_REQUIRE_TLS13 == NIOS_TLS_OPT_REQUIRE_TLS13, "options differ");
static_assert(WIFI_TLS_STEP_NO_READ == NIOS_TLS_STEP_NO_READ, "step flags differ");
static_assert(WIFI_TLS_REASON_NO_ENTROPY == NIOS_TLS_REASON_NO_ENTROPY, "reasons differ");
static_assert(WIFI_TLS_REASON_NO_TIME == NIOS_TLS_REASON_NO_TIME, "reasons differ");
static_assert(WIFI_TLS_REASON_NO_CUSTOM_CA == NIOS_TLS_REASON_NO_CUSTOM_CA, "reasons differ");
static_assert(WIFI_TLS_TIME_NONE == NIOS_TLS_TIME_NONE, "time sources differ");
static_assert(WIFI_TLS_TIME_NIOS == NIOS_TLS_TIME_NIOS, "time sources differ");
static_assert(WIFI_TLS_FAIL_VERSION_REFUSED == NIOS_TLS_FAIL_VERSION_REFUSED, "fail reasons differ");
static_assert(WIFI_TLS_FAIL_DOWNGRADE == NIOS_TLS_FAIL_DOWNGRADE, "fail reasons differ");
static_assert(WIFI_TLS_FAIL_NO_EMS == NIOS_TLS_FAIL_NO_EMS, "fail reasons differ");
static_assert(WIFI_TLS_FAIL_CERT_VERIFY == NIOS_TLS_FAIL_CERT_VERIFY, "fail reasons differ");
static_assert(WIFI_TLS_FAIL_PIN_MISMATCH == NIOS_TLS_FAIL_PIN_MISMATCH, "fail reasons differ");
static_assert(WIFI_TLS_FAIL_PEER_CLOSED == NIOS_TLS_FAIL_PEER_CLOSED, "fail reasons differ");
static_assert(WIFI_TLS_ALERT_NONE == NIOS_TLS_ALERT_NONE, "alerts differ");
static_assert(WIFI_TLS_REJECT_RSA_KEY_SHORT == NIOS_TLS_REJECT_RSA_KEY_SHORT, "rejects differ");
static_assert(WIFI_TLS_REJECT_CURVE == NIOS_TLS_REJECT_CURVE, "rejects differ");
static_assert(WIFI_TLS_REJECT_NOT_CA == NIOS_TLS_REJECT_NOT_CA, "rejects differ");
static_assert(WIFI_TLS_HANDSHAKING == TLS_STATE_HANDSHAKING, "states differ");
static_assert(WIFI_TLS_ESTABLISHED == TLS_STATE_ESTABLISHED, "states differ");
static_assert(WIFI_TLS_CLOSED == TLS_STATE_CLOSED, "states differ");
static_assert(WIFI_TLS_FAILED == TLS_STATE_FAILED, "states differ");
static_assert(WIFI_TLS_BUSY == DEDICATED_BUSY, "codes differ");
static_assert(WIFI_TLS_NO_MODULE == DEDICATED_NO_MODULE, "codes differ");
static_assert(WIFI_TLS_FOREIGN == DEDICATED_FOREIGN, "codes differ");
static_assert(WIFI_TLS_UNSENT == DEDICATED_UNSENT, "codes differ");

static bool is_answer(const uint8_t *reply, int size, uint8_t command, uint16_t sequence)
{
    const rpc_header_t *hdr = (const rpc_header_t *)reply;
    return (size >= (int)sizeof(rpc_header_t)) && (hdr->command == command) && (hdr->sequence == sequence);
}

// A bare rpc_espcmd_resp with an error: how the module refuses a command it
// does not know (ESP_ERR_NOT_SUPPORTED), or one it cannot start.
static bool bare_refusal(const uint8_t *reply, int size, int *esp_err)
{
    const rpc_espcmd_resp *result = (const rpc_espcmd_resp *)reply;
    if ((size == (int)sizeof(rpc_espcmd_resp)) && (result->esp_err != 0)) {
        *esp_err = result->esp_err;
        return true;
    }
    return false;
}

int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, int *esp_err, uint8_t *reason)
{
    const nios_tls_open_resp *result = (const nios_tls_open_resp *)reply;
    if (!is_answer(reply, size, NIOS_CMD_TLS_OPEN, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (bare_refusal(reply, size, esp_err)) {
        return WIFI_TLS_REFUSED;
    }
    if (size != (int)sizeof(nios_tls_open_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        *reason = result->reason;
        return WIFI_TLS_REFUSED;
    }
    return 0;
}

int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step)
{
    const nios_tls_step_resp *result = (const nios_tls_step_resp *)reply;
    const int header = offsetof(nios_tls_step_resp, data);
    if (!is_answer(reply, size, NIOS_CMD_TLS_STEP, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (bare_refusal(reply, size, &step->esp_err)) {
        return WIFI_TLS_REFUSED;
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
    bool no_mem = has_state && (result->esp_err == WIFI_TLS_ESP_NO_MEM);
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
    // The reasons come with FAILED only.
    if (!failed && (result->fail_reason != NIOS_TLS_FAIL_NONE)) {
        return WIFI_TLS_INVALID;
    }
    uint16_t ct = result->ct_out_len;
    uint16_t pt = result->pt_out_len;
    if ((ct > step->ct_out_room) || (pt > step->pt_out_room)) {
        return WIFI_TLS_INVALID;
    }
    // A step that was told not to read cannot have read anything.
    if ((step->flags & WIFI_TLS_STEP_NO_READ) && (pt != 0)) {
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
    step->alert_in = result->alert_in;
    step->alert_out = result->alert_out;
    step->fail_reason = result->fail_reason;
    step->verify_flags = result->verify_flags;
    return again ? WIFI_TLS_AGAIN : 0;
}

int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, uint8_t *ct_out, uint16_t room,
                        uint16_t *ct_out_len, int *esp_err)
{
    const nios_tls_close_resp *result = (const nios_tls_close_resp *)reply;
    const int header = offsetof(nios_tls_close_resp, data);
    if (!is_answer(reply, size, NIOS_CMD_TLS_CLOSE, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (bare_refusal(reply, size, esp_err)) {
        return WIFI_TLS_REFUSED;
    }
    if ((size < header) || (size != header + result->ct_out_len)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        return WIFI_TLS_REFUSED;
    }
    if (result->ct_out_len > room) {
        return WIFI_TLS_INVALID;
    }
    memcpy(ct_out, result->data, result->ct_out_len);
    *ct_out_len = result->ct_out_len;
    return 0;
}

int wifi_tls_take_stats(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_stats_t *stats, int *esp_err)
{
    const nios_tls_stats_resp *result = (const nios_tls_stats_resp *)reply;
    if (!is_answer(reply, size, NIOS_CMD_TLS_STATS, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (bare_refusal(reply, size, esp_err)) {
        return WIFI_TLS_REFUSED;
    }
    if (size != (int)sizeof(nios_tls_stats_resp)) {
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
    stats->entropy_source = result->entropy_source;
    stats->ems = result->ems;
    stats->block_max_ms = result->block_max_ms;
    memcpy(stats->spki_sha256, result->spki_sha256, sizeof(stats->spki_sha256));
    return 0;
}

int wifi_tls_take_close_all(const uint8_t *reply, int size, uint16_t sequence, int *esp_err)
{
    const rpc_espcmd_resp *result = (const rpc_espcmd_resp *)reply;
    if (!is_answer(reply, size, NIOS_CMD_TLS_CLOSE_ALL, sequence)) {
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

// Three answers are well formed (M3-SPEC 5.2): loaded (0, no reject), a parse
// error (an mbedTLS or PSA code, never ESP_FAIL, no reject) and a refusal of a
// certificate that parsed (ESP_ERR_INVALID_ARG with reject 1, 3 or 4).
// Anything else is not.
int wifi_tls_take_set_ca(const uint8_t *reply, int size, uint16_t sequence, int *esp_err, uint8_t *reject)
{
    const nios_tls_set_ca_resp *result = (const nios_tls_set_ca_resp *)reply;
    if (!is_answer(reply, size, NIOS_CMD_TLS_SET_CA, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (bare_refusal(reply, size, esp_err)) {
        return WIFI_TLS_REFUSED;
    }
    if (size != (int)sizeof(nios_tls_set_ca_resp)) {
        return WIFI_TLS_INVALID;
    }
    int err = result->esp_err;
    uint8_t why = result->reject;
    if ((err == 0) && (why == NIOS_TLS_REJECT_NONE)) {
        return 0;
    }
    bool parse_error = (err <= -2) && (why == NIOS_TLS_REJECT_NONE);
    bool refused = (err == WIFI_TLS_ESP_INVALID_ARG) &&
                   ((why == NIOS_TLS_REJECT_RSA_KEY_SHORT) || (why == NIOS_TLS_REJECT_CURVE) ||
                    (why == NIOS_TLS_REJECT_NOT_CA));
    if (!parse_error && !refused) {
        return WIFI_TLS_INVALID;
    }
    *esp_err = err;
    *reject = why;
    return WIFI_TLS_REFUSED;
}

typedef struct {
    const wifi_tls_open_t *open;
    int *esp_err;
    uint8_t *reason;
} open_call_t;

static int fill_open(uint8_t *request, void *context)
{
    const wifi_tls_open_t *o = ((open_call_t *)context)->open;
    nios_tls_open_req *args = (nios_tls_open_req *)request;
    args->trust = o->trust;
    args->sni_len = o->sni_len;
    args->slot = o->slot;
    args->time_source = o->time_source;
    args->unix_time = o->unix_time;
    args->tag = o->tag;
    args->opts = o->opts;
    args->reserved = 0;
    args->ca_tag = o->ca_tag;
    args->reserved2 = 0;
    if (o->pin) {
        memcpy(args->pin, o->pin, NIOS_TLS_PIN_LEN);
    } else {
        memset(args->pin, 0, NIOS_TLS_PIN_LEN);
    }
    if (o->sni_len) {
        memcpy(args->sni, o->sni, o->sni_len);
    }
    return offsetof(nios_tls_open_req, sni) + o->sni_len;
}

static int take_open(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    open_call_t *c = (open_call_t *)context;
    return wifi_tls_take_open(reply, size, sequence, c->esp_err, c->reason);
}

static void set_cancel(dedicated_call_t *call, const wifi_tls_cancel_t *cancel)
{
    call->cancel = cancel ? cancel->cancelled : NULL;
    call->cancel_context = cancel ? cancel->context : NULL;
}

int wifi_tls_open(const wifi_tls_open_t *open, uint32_t timeout_ms, const wifi_tls_cancel_t *cancel, int *esp_err,
                  uint8_t *reason)
{
    *esp_err = 0;
    *reason = 0;
    if ((open->sni_len > WIFI_TLS_MAX_SNI) || (open->sni_len && !open->sni)) {
        return WIFI_TLS_TOO_LONG;
    }
    open_call_t args = { open, esp_err, reason };
    dedicated_call_t call = { "TLS Open", NIOS_CMD_TLS_OPEN, timeout_ms, fill_open, take_open, &args };
    set_cancel(&call, cancel);
    return wifi_dedicated_call(&call);
}

typedef struct {
    uint8_t slot;
    uint16_t tag;
    wifi_tls_step_t *step;
} step_call_t;

static int fill_step(uint8_t *request, void *context)
{
    step_call_t *c = (step_call_t *)context;
    wifi_tls_step_t *step = c->step;
    nios_tls_step_req *args = (nios_tls_step_req *)request;
    args->slot = c->slot;
    args->flags = step->flags;
    args->tag = c->tag;
    args->ct_in_len = step->ct_in_len;
    args->pt_in_len = step->pt_in_len;
    memcpy(args->data, step->ct_in, step->ct_in_len);
    memcpy(args->data + step->ct_in_len, step->pt_in, step->pt_in_len);
    return offsetof(nios_tls_step_req, data) + step->ct_in_len + step->pt_in_len;
}

static int take_step(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    return wifi_tls_take_step(reply, size, sequence, ((step_call_t *)context)->step);
}

int wifi_tls_step(uint8_t slot, uint16_t tag, wifi_tls_step_t *step, uint32_t timeout_ms,
                  const wifi_tls_cancel_t *cancel)
{
    step->ct_out_len = 0;
    step->pt_out_len = 0;
    step->state = WIFI_TLS_UNKNOWN;
    step->esp_err = 0;
    step->alert_in = WIFI_TLS_ALERT_NONE;
    step->alert_out = WIFI_TLS_ALERT_NONE;
    step->fail_reason = WIFI_TLS_FAIL_NONE;
    step->verify_flags = 0;
    if ((int)step->ct_in_len + step->pt_in_len > WIFI_TLS_STEP_MAX_IN) {
        return WIFI_TLS_TOO_LONG;
    }
    step_call_t args = { slot, tag, step };
    dedicated_call_t call = { "TLS Step", NIOS_CMD_TLS_STEP, timeout_ms, fill_step, take_step, &args };
    set_cancel(&call, cancel);
    return wifi_dedicated_call(&call);
}

typedef struct {
    uint8_t slot;
    uint16_t tag;
    wifi_tls_stats_t *stats;
    uint8_t *ct_out;
    uint16_t room;
    uint16_t *ct_out_len;
    int *esp_err;
} session_call_t;

// CLOSE and STATS carry the same argument.
static int fill_session(uint8_t *request, void *context)
{
    session_call_t *c = (session_call_t *)context;
    nios_tls_session_req *args = (nios_tls_session_req *)request;
    args->slot = c->slot;
    args->reserved = 0;
    args->tag = c->tag;
    return sizeof(nios_tls_session_req);
}

static int take_close(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    session_call_t *c = (session_call_t *)context;
    return wifi_tls_take_close(reply, size, sequence, c->ct_out, c->room, c->ct_out_len, c->esp_err);
}

int wifi_tls_close(uint8_t slot, uint16_t tag, uint8_t *ct_out, uint16_t room, uint16_t *ct_out_len, int *esp_err,
                   uint32_t timeout_ms, const wifi_tls_cancel_t *cancel)
{
    *esp_err = 0;
    *ct_out_len = 0;
    session_call_t args = { slot, tag, NULL, ct_out, room, ct_out_len, esp_err };
    dedicated_call_t call = { "TLS Close", NIOS_CMD_TLS_CLOSE, timeout_ms, fill_session, take_close, &args };
    set_cancel(&call, cancel);
    return wifi_dedicated_call(&call);
}

static int take_stats(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    session_call_t *c = (session_call_t *)context;
    return wifi_tls_take_stats(reply, size, sequence, c->stats, c->esp_err);
}

int wifi_tls_stats(uint8_t slot, uint16_t tag, wifi_tls_stats_t *stats, int *esp_err, uint32_t timeout_ms,
                   const wifi_tls_cancel_t *cancel)
{
    *esp_err = 0;
    session_call_t args = { slot, tag, stats, NULL, 0, NULL, esp_err };
    dedicated_call_t call = { "TLS Stats", NIOS_CMD_TLS_STATS, timeout_ms, fill_session, take_stats, &args };
    set_cancel(&call, cancel);
    return wifi_dedicated_call(&call);
}

static int fill_close_all(uint8_t *request, void *context)
{
    return sizeof(nios_tls_close_all_req);
}

static int take_close_all(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    return wifi_tls_take_close_all(reply, size, sequence, (int *)context);
}

int wifi_tls_close_all(int *esp_err, uint32_t timeout_ms)
{
    *esp_err = 0;
    const dedicated_call_t call = { "TLS Close All", NIOS_CMD_TLS_CLOSE_ALL, timeout_ms, fill_close_all,
                                    take_close_all, esp_err };
    return wifi_dedicated_call(&call);
}

typedef struct {
    const uint8_t *der;
    uint16_t der_len;
    uint16_t ca_tag;
    int *esp_err;
    uint8_t *reject;
} set_ca_call_t;

static int fill_set_ca(uint8_t *request, void *context)
{
    set_ca_call_t *c = (set_ca_call_t *)context;
    nios_tls_set_ca_req *args = (nios_tls_set_ca_req *)request;
    args->der_len = c->der_len;
    args->ca_tag = c->ca_tag;
    memcpy(args->der, c->der, c->der_len);
    return offsetof(nios_tls_set_ca_req, der) + c->der_len;
}

static int take_set_ca(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    set_ca_call_t *c = (set_ca_call_t *)context;
    return wifi_tls_take_set_ca(reply, size, sequence, c->esp_err, c->reject);
}

int wifi_tls_set_ca(const uint8_t *der, uint16_t der_len, uint16_t ca_tag, int *esp_err, uint8_t *reject,
                    uint32_t timeout_ms, const wifi_tls_cancel_t *cancel)
{
    *esp_err = 0;
    *reject = 0;
    if (der_len > WIFI_TLS_CA_MAX) {
        return WIFI_TLS_TOO_LONG;
    }
    set_ca_call_t args = { der, der_len, ca_tag, esp_err, reject };
    dedicated_call_t call = { "TLS Set CA", NIOS_CMD_TLS_SET_CA, timeout_ms, fill_set_ca, take_set_ca, &args };
    set_cancel(&call, cancel);
    return wifi_dedicated_call(&call);
}
