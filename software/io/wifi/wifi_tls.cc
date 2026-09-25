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

// The layout the module sends and this code reads. Checked here so that the
// firmware build itself fails if it ever changes.
static_assert(sizeof(rpc_espcmd_resp) == 8, "rpc_espcmd_resp changed");
static_assert(offsetof(rpc_espcmd_resp, esp_err) == 4, "rpc_espcmd_resp changed");
static_assert(sizeof(rpc_tls_open_req) == 6, "rpc_tls_open_req changed");
static_assert(offsetof(rpc_tls_open_req, flags) == 4, "rpc_tls_open_req changed");
static_assert(offsetof(rpc_tls_open_req, sni_len) == 5, "rpc_tls_open_req changed");
static_assert(offsetof(rpc_tls_open_req, sni) == 6, "rpc_tls_open_req changed");
static_assert(sizeof(rpc_tls_open_resp) == 12, "rpc_tls_open_resp changed");
static_assert(offsetof(rpc_tls_open_resp, esp_err) == 4, "rpc_tls_open_resp changed");
static_assert(offsetof(rpc_tls_open_resp, session) == 8, "rpc_tls_open_resp changed");
static_assert(sizeof(rpc_tls_step_req) == 10, "rpc_tls_step_req changed");
static_assert(offsetof(rpc_tls_step_req, session) == 4, "rpc_tls_step_req changed");
static_assert(offsetof(rpc_tls_step_req, ct_in_len) == 6, "rpc_tls_step_req changed");
static_assert(offsetof(rpc_tls_step_req, pt_in_len) == 8, "rpc_tls_step_req changed");
static_assert(offsetof(rpc_tls_step_req, data) == 10, "rpc_tls_step_req changed");
static_assert(sizeof(rpc_tls_step_resp) == 16, "rpc_tls_step_resp changed");
static_assert(offsetof(rpc_tls_step_resp, esp_err) == 4, "rpc_tls_step_resp changed");
static_assert(offsetof(rpc_tls_step_resp, state) == 8, "rpc_tls_step_resp changed");
static_assert(offsetof(rpc_tls_step_resp, ct_out_len) == 10, "rpc_tls_step_resp changed");
static_assert(offsetof(rpc_tls_step_resp, pt_out_len) == 12, "rpc_tls_step_resp changed");
static_assert(offsetof(rpc_tls_step_resp, data) == 16, "rpc_tls_step_resp changed");
static_assert(sizeof(rpc_tls_close_req) == 6, "rpc_tls_close_req changed");
static_assert(offsetof(rpc_tls_close_req, session) == 4, "rpc_tls_close_req changed");
static_assert(sizeof(rpc_tls_stats_req) == 6, "rpc_tls_stats_req changed");
static_assert(offsetof(rpc_tls_stats_req, session) == 4, "rpc_tls_stats_req changed");
static_assert(sizeof(rpc_tls_stats_resp) == 48, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, esp_err) == 4, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, heap_free) == 8, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, heap_min_ever) == 12, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, largest_block) == 16, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, ct_in_bytes) == 20, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, ct_out_bytes) == 24, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, pt_in_bytes) == 28, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, pt_out_bytes) == 32, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, handshake_us) == 36, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, tls_version) == 40, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, ciphersuite) == 42, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, group) == 44, "rpc_tls_stats_resp changed");
static_assert(offsetof(rpc_tls_stats_resp, reserved) == 46, "rpc_tls_stats_resp changed");

// A full step, either way, fits one buffer.
static_assert(offsetof(rpc_tls_step_req, data) + TLS_STEP_MAX_IN <= CMD_BUF_SIZE, "step request too large");
static_assert(offsetof(rpc_tls_step_resp, data) + TLS_STEP_MAX_OUT <= CMD_BUF_SIZE, "step reply too large");

// What wifi_tls.h repeats.
static_assert(WIFI_TLS_FLAG_VERIFY == TLS_FLAG_VERIFY, "flags differ");
static_assert(WIFI_TLS_FLAG_CA_BUNDLE == TLS_FLAG_CA_BUNDLE, "flags differ");
static_assert(WIFI_TLS_FLAG_TEST_CA == TLS_FLAG_TEST_CA, "flags differ");
static_assert(WIFI_TLS_SESSION_GLOBAL == TLS_SESSION_GLOBAL, "sessions differ");
static_assert(WIFI_TLS_STEP_MAX_IN == TLS_STEP_MAX_IN, "step sizes differ");
static_assert(WIFI_TLS_HANDSHAKING == TLS_STATE_HANDSHAKING, "states differ");
static_assert(WIFI_TLS_ESTABLISHED == TLS_STATE_ESTABLISHED, "states differ");
static_assert(WIFI_TLS_CLOSED == TLS_STATE_CLOSED, "states differ");
static_assert(WIFI_TLS_FAILED == TLS_STATE_FAILED, "states differ");
static_assert(WIFI_TLS_BUSY == DEDICATED_BUSY, "codes differ");
static_assert(WIFI_TLS_NO_MODULE == DEDICATED_NO_MODULE, "codes differ");
static_assert(WIFI_TLS_FOREIGN == DEDICATED_FOREIGN, "codes differ");
static_assert(WIFI_TLS_UNSENT == DEDICATED_UNSENT, "codes differ");

// How long each call waits for its answer. A step can carry a whole flight of
// the handshake, and so the key exchange and the chain verification, which
// take the module up to about a second. A close can find the module still
// busy with a step whose answer came too late.
#define OPEN_TIMEOUT_MS  2000
#define STEP_TIMEOUT_MS  5000
#define CLOSE_TIMEOUT_MS 5000
#define STATS_TIMEOUT_MS 1000

static bool is_answer(const uint8_t *reply, int size, uint8_t command, uint16_t sequence)
{
    const rpc_header_t *hdr = (const rpc_header_t *)reply;
    return (size >= (int)sizeof(rpc_header_t)) && (hdr->command == command) && (hdr->sequence == sequence);
}

int wifi_tls_take_open(const uint8_t *reply, int size, uint16_t sequence, uint8_t *session, int *esp_err)
{
    const rpc_tls_open_resp *result = (const rpc_tls_open_resp *)reply;
    if (!is_answer(reply, size, CMD_TLS_OPEN, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (size < (int)sizeof(rpc_espcmd_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        return WIFI_TLS_REFUSED;
    }
    if ((size < (int)offsetof(rpc_tls_open_resp, session) + 1) || (result->session == TLS_SESSION_GLOBAL)) {
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
    if (size < (int)sizeof(rpc_espcmd_resp)) {
        return WIFI_TLS_INVALID;
    }
    bool has_state = (size >= header) && (result->state <= TLS_STATE_FAILED);
    if ((result->esp_err != 0) && !(has_state && (result->state == TLS_STATE_FAILED))) {
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
    if ((ct > step->ct_out_room) || (pt > step->pt_out_room) || (size < header + ct + pt)) {
        return WIFI_TLS_INVALID;
    }
    // Plaintext only from a session that has finished its handshake.
    if ((pt != 0) && (result->state != TLS_STATE_ESTABLISHED) && (result->state != TLS_STATE_CLOSED)) {
        return WIFI_TLS_INVALID;
    }
    memcpy(step->ct_out, result->data, ct);
    memcpy(step->pt_out, result->data + ct, pt);
    step->ct_out_len = ct;
    step->pt_out_len = pt;
    step->state = result->state;
    step->esp_err = result->esp_err;
    return 0;
}

int wifi_tls_take_close(const uint8_t *reply, int size, uint16_t sequence, int *esp_err)
{
    const rpc_espcmd_resp *result = (const rpc_espcmd_resp *)reply;
    if (!is_answer(reply, size, CMD_TLS_CLOSE, sequence)) {
        return WIFI_TLS_FOREIGN;
    }
    if (size < (int)sizeof(rpc_espcmd_resp)) {
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
    if (size < (int)sizeof(rpc_espcmd_resp)) {
        return WIFI_TLS_INVALID;
    }
    if (result->esp_err != 0) {
        *esp_err = result->esp_err;
        return WIFI_TLS_REFUSED;
    }
    if (size < (int)offsetof(rpc_tls_stats_resp, reserved)) {
        return WIFI_TLS_INVALID;
    }
    stats->heap_free = result->heap_free;
    stats->heap_min_ever = result->heap_min_ever;
    stats->largest_block = result->largest_block;
    stats->ct_in_bytes = result->ct_in_bytes;
    stats->ct_out_bytes = result->ct_out_bytes;
    stats->pt_in_bytes = result->pt_in_bytes;
    stats->pt_out_bytes = result->pt_out_bytes;
    stats->handshake_us = result->handshake_us;
    stats->tls_version = result->tls_version;
    stats->ciphersuite = result->ciphersuite;
    stats->group = result->group;
    return 0;
}

typedef struct {
    uint8_t flags;
    const char *sni;
    uint8_t sni_len;
    uint8_t *session;
    int *esp_err;
} open_call_t;

static int fill_open(uint8_t *request, void *context)
{
    open_call_t *c = (open_call_t *)context;
    rpc_tls_open_req *args = (rpc_tls_open_req *)request;
    args->flags = c->flags;
    args->sni_len = c->sni_len;
    memcpy(args->sni, c->sni, c->sni_len);
    return offsetof(rpc_tls_open_req, sni) + c->sni_len;
}

static int take_open(const uint8_t *reply, int size, uint16_t sequence, void *context)
{
    open_call_t *c = (open_call_t *)context;
    return wifi_tls_take_open(reply, size, sequence, c->session, c->esp_err);
}

int wifi_tls_open(uint8_t flags, const char *sni, uint8_t *session, int *esp_err)
{
    *esp_err = 0;
    size_t sni_len = sni ? strlen(sni) : 0;
    if (sni_len > WIFI_TLS_MAX_SNI) {
        return WIFI_TLS_TOO_LONG;
    }
    open_call_t args = { flags, sni, (uint8_t)sni_len, session, esp_err };
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

static int fill_session(uint8_t *request, void *context)
{
    // CLOSE and STATS carry the same argument.
    static_assert(offsetof(rpc_tls_close_req, session) == offsetof(rpc_tls_stats_req, session), "requests differ");
    static_assert(sizeof(rpc_tls_close_req) == sizeof(rpc_tls_stats_req), "requests differ");
    rpc_tls_close_req *args = (rpc_tls_close_req *)request;
    memset(&args->session, 0, sizeof(rpc_tls_close_req) - offsetof(rpc_tls_close_req, session)); // and the padding
    args->session = ((session_call_t *)context)->session;
    return sizeof(rpc_tls_close_req);
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
