/*
 * Host tests for the TLS calls to the WiFi module (software/io/wifi/wifi_tls.cc)
 * and for the channel they share with GET_RANDOM (wifi_dedicated.cc).
 *
 *   make -C target/pc/linux/wifitls test
 *
 * The real wifi_tls.cc, wifi_dedicated.cc and wifi_random.cc are compiled
 * here; only the UART, the queue, the tick and the module are the world's.
 */
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include "world.h"
#include "wifi_dedicated.h"
#include "wifi_tls.h"
#include "check.h"
#undef printf

int failures;
int checks;

void check(bool condition, const char *what, ...)
{
    char line[300];
    va_list ap;
    va_start(ap, what);
    vsnprintf(line, sizeof(line), what, ap);
    va_end(ap);
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", line);
    } else {
        printf("  ok    %s\n", line);
    }
}

void test_dedicated(void);

#define SEQUENCE 0x1234

// Word aligned, as the data of a command_buf_t is.
static union {
    uint32_t align;
    uint8_t bytes[CMD_BUF_SIZE];
} reply;

static void header(uint8_t command)
{
    memset(reply.bytes, 0, sizeof(reply.bytes));
    rpc_header_t *hdr = (rpc_header_t *)reply.bytes;
    hdr->command = command;
    hdr->thread = WIFI_DEDICATED_THREAD;
    hdr->sequence = SEQUENCE;
}

// A step answer: state, esp_err, ct bytes of 0xC0+i and pt bytes of 0x50+i.
static int step_reply(uint8_t state, int esp_err, uint16_t ct, uint16_t pt)
{
    header(CMD_TLS_STEP);
    rpc_tls_step_resp *r = (rpc_tls_step_resp *)reply.bytes;
    r->esp_err = esp_err;
    r->state = state;
    r->ct_out_len = ct;
    r->pt_out_len = pt;
    for (int i = 0; i < ct; i++) {
        r->data[i] = (uint8_t)(0xC0 + i);
    }
    for (int i = 0; i < pt; i++) {
        r->data[ct + i] = (uint8_t)(0x50 + i);
    }
    return offsetof(rpc_tls_step_resp, data) + ct + pt;
}

static uint8_t ct_out[CMD_BUF_SIZE];
static uint8_t pt_out[CMD_BUF_SIZE];

static void fresh_step(wifi_tls_step_t *st, uint16_t room)
{
    memset(st, 0, sizeof(*st));
    memset(ct_out, 0xEE, sizeof(ct_out));
    memset(pt_out, 0xEE, sizeof(pt_out));
    st->ct_out = ct_out;
    st->pt_out = pt_out;
    st->ct_out_room = room;
    st->pt_out_room = room;
    st->ct_out_len = 0x7777;
    st->pt_out_len = 0x7777;
    st->state = WIFI_TLS_UNKNOWN;
    st->esp_err = 0;
}

static bool untouched(const uint8_t *buf)
{
    for (int i = 0; i < CMD_BUF_SIZE; i++) {
        if (buf[i] != 0xEE) {
            return false;
        }
    }
    return true;
}

static bool nothing_out(const wifi_tls_step_t *st)
{
    return untouched(ct_out) && untouched(pt_out) && (st->ct_out_len == 0x7777) && (st->pt_out_len == 0x7777);
}

static void test_take_step(void)
{
    printf("The check on a STEP answer\n");
    wifi_tls_step_t st;
    const uint16_t sizes[][2] = { { 0, 0 }, { 1, 0 }, { 0, 1 }, { 255, 1 }, { 256, 0 }, { 300, 700 }, { 1024, 0 }, { 0, 1024 } };
    bool all = true;
    for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        uint16_t ct = sizes[k][0], pt = sizes[k][1];
        int size = step_reply(TLS_STATE_ESTABLISHED, 0, ct, pt);
        fresh_step(&st, 1024);
        int r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
        bool ok = (r == 0) && (st.ct_out_len == ct) && (st.pt_out_len == pt) && (st.state == WIFI_TLS_ESTABLISHED) &&
                  (memcmp(ct_out, ((rpc_tls_step_resp *)reply.bytes)->data, ct) == 0) &&
                  (memcmp(pt_out, ((rpc_tls_step_resp *)reply.bytes)->data + ct, pt) == 0) &&
                  (ct_out[ct] == 0xEE) && (pt_out[pt] == 0xEE);
        if (!ok) {
            printf("        ct %u pt %u: returned %d\n", ct, pt, r);
        }
        all = all && ok;
    }
    check(all, "an ESTABLISHED answer hands over exactly its bytes, at lengths from 0 to 1024 and past 255");

    int size = step_reply(TLS_STATE_ESTABLISHED, 0, 10, 10);
    int foreign = 0;
    for (int command = 0; command < 256; command++) {
        if (command == CMD_TLS_STEP) {
            continue;
        }
        ((rpc_header_t *)reply.bytes)->command = command;
        fresh_step(&st, 1024);
        foreign += (wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st) == WIFI_TLS_FOREIGN) && nothing_out(&st) &&
                   (st.state == WIFI_TLS_UNKNOWN);
    }
    check(foreign == 255, "an answer to any other command is foreign and changes nothing (%d of 255)", foreign);

    const int offsets[] = { 1, -1, 256, -256, 0x8000 };
    int late = 0;
    for (unsigned k = 0; k < sizeof(offsets) / sizeof(offsets[0]); k++) {
        size = step_reply(TLS_STATE_ESTABLISHED, 0, 10, 10);
        ((rpc_header_t *)reply.bytes)->sequence = (uint16_t)(SEQUENCE + offsets[k]);
        fresh_step(&st, 1024);
        late += (wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st) == WIFI_TLS_FOREIGN) && nothing_out(&st);
    }
    check(late == 5, "an answer to another sequence, 256 or 32768 away included, is foreign");

    int shorts = 0;
    size = step_reply(TLS_STATE_ESTABLISHED, 0, 10, 10);
    for (int s = 0; s < 4; s++) {
        fresh_step(&st, 1024);
        shorts += (wifi_tls_take_step(reply.bytes, s, SEQUENCE, &st) == WIFI_TLS_FOREIGN) && nothing_out(&st);
    }
    for (int s = 4; s < 8; s++) {
        fresh_step(&st, 1024);
        shorts += (wifi_tls_take_step(reply.bytes, s, SEQUENCE, &st) == WIFI_TLS_INVALID) && nothing_out(&st);
    }
    for (int s = 8; s < 36; s++) {
        fresh_step(&st, 1024);
        shorts += (wifi_tls_take_step(reply.bytes, s, SEQUENCE, &st) == WIFI_TLS_INVALID) && nothing_out(&st);
    }
    for (int s = 37; s < 60; s++) {
        fresh_step(&st, 1024);
        shorts += (wifi_tls_take_step(reply.bytes, s, SEQUENCE, &st) == WIFI_TLS_INVALID) && nothing_out(&st);
    }
    check(shorts == 59, "an answer of any size but its own (36) hands out nothing (%d of 59)", shorts);

    size = step_reply(TLS_STATE_ESTABLISHED, 0, 300, 700);
    fresh_step(&st, 1024);
    int r = wifi_tls_take_step(reply.bytes, size - 1, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "one byte short at lengths past 255 hands out nothing");
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size + 1, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "one byte long hands out nothing either");

    size = step_reply(TLS_STATE_ESTABLISHED, 0, 20, 0);
    fresh_step(&st, 19);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "more ciphertext than the caller has room for is invalid, not cut");
    size = step_reply(TLS_STATE_ESTABLISHED, 0, 0, 20);
    fresh_step(&st, 19);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "more plaintext than the caller has room for is invalid, not cut");

    size = step_reply(TLS_STATE_HANDSHAKING, 0, 5, 3);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "plaintext during the handshake is invalid, and none is handed out");
    size = step_reply(TLS_STATE_FAILED, -0x2700, 5, 3);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == 0) && (st.state == WIFI_TLS_FAILED) && (st.ct_out_len == 5) && (st.pt_out_len == 0) && untouched(pt_out),
          "plaintext read before a session failed is withheld; the failure and the alert come through");

    size = step_reply(TLS_STATE_HANDSHAKING, 0x101, 9, 0);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_AGAIN) && (st.esp_err == 0x101) && (st.ct_out_len == 9) && (ct_out[8] == 0xC8) &&
          (st.state == WIFI_TLS_HANDSHAKING),
          "ESP_ERR_NO_MEM: the input was not taken (AGAIN), and the output is handed over all the same");
    size = step_reply(TLS_STATE_ESTABLISHED, 0x101, 4, 6);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_AGAIN) && (st.ct_out_len == 4) && (st.pt_out_len == 6) && (pt_out[0] == 0x50),
          "ESP_ERR_NO_MEM while established hands over plaintext too");
    size = step_reply(TLS_STATE_HANDSHAKING, 0x101, 4, 6);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "ESP_ERR_NO_MEM keeps the rule: no plaintext during the handshake");
    size = step_reply(TLS_STATE_CLOSED, 0x101, 4, 0);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_REFUSED) && nothing_out(&st) && (st.state == WIFI_TLS_CLOSED),
          "ESP_ERR_NO_MEM from a session that is gone is refused");
    size = step_reply(TLS_STATE_ESTABLISHED, 0x101, 20, 0);
    fresh_step(&st, 19);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_INVALID) && nothing_out(&st), "ESP_ERR_NO_MEM with more than there is room for is invalid");
    size = step_reply(TLS_STATE_CLOSED, 0, 0, 3);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == 0) && (st.pt_out_len == 3) && (st.state == WIFI_TLS_CLOSED), "the last plaintext before a close is handed out");

    size = step_reply(TLS_STATE_FAILED, -0x2700, 7, 0);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == 0) && (st.state == WIFI_TLS_FAILED) && (st.esp_err == -0x2700) && (st.ct_out_len == 7) &&
          (ct_out[0] == 0xC0) && untouched(pt_out),
          "a failed handshake is an answer: FAILED, its error, and the alert for the server");

    size = step_reply(TLS_STATE_HANDSHAKING, 0x102, 5, 0);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_REFUSED) && (st.esp_err == 0x102) && (st.state == WIFI_TLS_HANDSHAKING) && nothing_out(&st),
          "an error in any other state is refused, with its error and state, and nothing handed out");
    int cut = 0;
    for (int s = 8; s < 16; s++) {
        fresh_step(&st, 1024);
        cut += (wifi_tls_take_step(reply.bytes, s, SEQUENCE, &st) == WIFI_TLS_INVALID) && nothing_out(&st) &&
               (st.esp_err == 0);
    }
    check(cut == 8, "an error in an answer cut short is invalid, and nothing of it is taken (%d of 8)", cut);
    size = step_reply(9, 0x102, 0, 0);
    fresh_step(&st, 1024);
    r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
    check((r == WIFI_TLS_REFUSED) && (st.esp_err == 0x102) && (st.state == WIFI_TLS_UNKNOWN),
          "an error with a state that does not exist is refused, with the state unknown");

    const int errors[] = { 1, -1, 0x100, 0x3000, 0x10000, INT_MIN, INT_MAX };
    int refused = 0;
    for (unsigned k = 0; k < sizeof(errors) / sizeof(errors[0]); k++) {
        size = step_reply(TLS_STATE_ESTABLISHED, errors[k], 5, 5);
        fresh_step(&st, 1024);
        refused += (wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st) == WIFI_TLS_REFUSED) && nothing_out(&st);
    }
    check(refused == 7, "any error bit refuses an ESTABLISHED answer, low byte zero or not (%d of 7)", refused);

    int states = 0;
    for (int state = 4; state < 256; state++) {
        size = step_reply((uint8_t)state, 0, 5, 5);
        fresh_step(&st, 1024);
        states += (wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st) == WIFI_TLS_INVALID) && nothing_out(&st);
    }
    check(states == 252, "a state that does not exist is invalid (%d of 252)", states);

    // Random answers: whatever comes back, bytes are only handed out whole and
    // only from an answer that holds them, and plaintext only once established.
    world_reset(99, NULL, true);
    int broken = 0;
    for (int n = 0; n < 300000; n++) {
        for (int i = 0; i < 64; i++) {
            reply.bytes[i] = (uint8_t)world_rand(256);
        }
        rpc_tls_step_resp *res = (rpc_tls_step_resp *)reply.bytes;
        if (world_rand(2)) {
            res->hdr.command = CMD_TLS_STEP;
            res->hdr.sequence = SEQUENCE;
        }
        if (world_rand(2)) {
            res->esp_err = world_rand(2) ? 0 : (world_rand(2) ? -0x2700 : 0x101);
        }
        if (world_rand(2)) {
            res->state = world_rand(5);
        }
        if (world_rand(2)) {
            res->ct_out_len = world_rand(1100);
            res->pt_out_len = world_rand(1100);
        }
        size = world_rand(2) ? (int)world_rand(CMD_BUF_SIZE + 1)
                             : (int)(offsetof(rpc_tls_step_resp, data) + res->ct_out_len + res->pt_out_len);
        if (size > CMD_BUF_SIZE) {
            size = CMD_BUF_SIZE;
        }
        uint16_t room = (uint16_t)world_rand(1100);
        fresh_step(&st, room);
        r = wifi_tls_take_step(reply.bytes, size, SEQUENCE, &st);
        if (r == 0) {
            uint16_t ct = res->ct_out_len, pt = res->pt_out_len;
            bool good = (ct <= room) && (pt <= room) && (size == (int)offsetof(rpc_tls_step_resp, data) + ct + pt) &&
                        (st.ct_out_len == ct) && ((st.pt_out_len == pt) || (res->state == TLS_STATE_FAILED)) &&
                        (res->state <= TLS_STATE_FAILED) &&
                        ((pt == 0) || (res->state != TLS_STATE_HANDSHAKING)) && // withheld when FAILED, below
                        ((res->esp_err == 0) || (res->state == TLS_STATE_FAILED)) &&
                        (memcmp(ct_out, res->data, ct) == 0) &&
                        ((res->state == TLS_STATE_FAILED) ? ((st.pt_out_len == 0) && untouched(pt_out))
                                                          : (memcmp(pt_out, res->data + ct, pt) == 0));
            if (res->state == TLS_STATE_FAILED) {
                good = good && (ct <= room) && (size >= (int)offsetof(rpc_tls_step_resp, data) + ct + pt) &&
                       (st.ct_out_len == ct);
            }
            broken += !good;
        } else if (r == WIFI_TLS_AGAIN) {
            uint16_t ct = res->ct_out_len, pt = res->pt_out_len;
            bool good = (res->esp_err == 0x101) && ((res->state == TLS_STATE_HANDSHAKING) || (res->state == TLS_STATE_ESTABLISHED)) &&
                        (ct <= room) && (pt <= room) && (size == (int)offsetof(rpc_tls_step_resp, data) + ct + pt) &&
                        ((pt == 0) || (res->state == TLS_STATE_ESTABLISHED)) && (st.ct_out_len == ct) &&
                        (st.pt_out_len == pt) && (memcmp(ct_out, res->data, ct) == 0) &&
                        (memcmp(pt_out, res->data + ct, pt) == 0);
            broken += !good;
        } else {
            broken += !nothing_out(&st);
        }
    }
    check(broken == 0, "300000 random answers: bytes only whole, only from an answer that holds them (%d not)", broken);
}

static void test_take_others(void)
{
    printf("The checks on OPEN, CLOSE and STATS answers\n");
    uint8_t session = 0x77;
    int esp_err = 0;
    uint8_t reason = 0x77;

    header(CMD_TLS_OPEN);
    ((rpc_tls_open_resp *)reply.bytes)->session = 1;
    int r = wifi_tls_take_open(reply.bytes, sizeof(rpc_tls_open_resp), SEQUENCE, &session, &esp_err, &reason);
    check((r == 0) && (session == 1), "OPEN: the answer gives the session");
    session = 0x77;
    r = wifi_tls_take_open(reply.bytes, 9, SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_INVALID) && (session == 0x77), "OPEN: nine bytes, the session but not the padding, is invalid");
    r = wifi_tls_take_open(reply.bytes, 13, SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_INVALID) && (session == 0x77), "OPEN: thirteen bytes is invalid");
    session = 0x77;
    r = wifi_tls_take_open(reply.bytes, 8, SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_INVALID) && (session == 0x77), "OPEN: without the session byte it is invalid");
    ((rpc_tls_open_resp *)reply.bytes)->session = TLS_SESSION_GLOBAL;
    r = wifi_tls_take_open(reply.bytes, sizeof(rpc_tls_open_resp), SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_INVALID) && (session == 0x77), "OPEN: session 0xFF, which names the module, is invalid");
    ((rpc_tls_open_resp *)reply.bytes)->esp_err = 0x103;
    ((rpc_tls_open_resp *)reply.bytes)->reason = TLS_OPEN_REASON_NO_TIME;
    r = wifi_tls_take_open(reply.bytes, sizeof(rpc_tls_open_resp), SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_REFUSED) && (esp_err == 0x103) && (session == 0x77) && (reason == WIFI_TLS_REASON_NO_TIME),
          "OPEN: refused with ESP_ERR_INVALID_STATE, and the reason (no time) that tells it from no entropy");
    reason = 0x77;
    esp_err = 0;
    r = wifi_tls_take_open(reply.bytes, 10, SEQUENCE, &session, &esp_err, &reason);
    check((r == WIFI_TLS_INVALID) && (reason == 0x77) && (esp_err == 0),
          "OPEN: a refusal of the wrong size is invalid, and neither error nor reason is taken");
    ((rpc_header_t *)reply.bytes)->command = CMD_TLS_STEP;
    r = wifi_tls_take_open(reply.bytes, sizeof(rpc_tls_open_resp), SEQUENCE, &session, &esp_err, &reason);
    check(r == WIFI_TLS_FOREIGN, "OPEN: a STEP answer is foreign");

    header(CMD_TLS_CLOSE);
    esp_err = 0;
    r = wifi_tls_take_close(reply.bytes, sizeof(rpc_espcmd_resp), SEQUENCE, &esp_err);
    check(r == 0, "CLOSE: done");
    r = wifi_tls_take_close(reply.bytes, sizeof(rpc_espcmd_resp) - 1, SEQUENCE, &esp_err);
    check(r == WIFI_TLS_INVALID, "CLOSE: short is invalid");
    r = wifi_tls_take_close(reply.bytes, sizeof(rpc_espcmd_resp) + 1, SEQUENCE, &esp_err);
    check(r == WIFI_TLS_INVALID, "CLOSE: long is invalid");
    ((rpc_espcmd_resp *)reply.bytes)->esp_err = 0x102;
    r = wifi_tls_take_close(reply.bytes, sizeof(rpc_espcmd_resp), SEQUENCE, &esp_err);
    check((r == WIFI_TLS_REFUSED) && (esp_err == 0x102), "CLOSE: refused, with its error");
    ((rpc_header_t *)reply.bytes)->sequence = SEQUENCE + 1;
    r = wifi_tls_take_close(reply.bytes, sizeof(rpc_espcmd_resp), SEQUENCE, &esp_err);
    check(r == WIFI_TLS_FOREIGN, "CLOSE: another sequence is foreign");

    header(CMD_TLS_STATS);
    rpc_tls_stats_resp *s = (rpc_tls_stats_resp *)reply.bytes;
    s->heap_free = 100001;
    s->heap_min = 90002;
    s->largest_block = 50003;
    s->ct_in_bytes = 4;
    s->ct_out_bytes = 5;
    s->pt_in_bytes = 6;
    s->pt_out_bytes = 7;
    s->handshake_us = 456789;
    s->tls_version = 0x0304;
    s->ciphersuite = 0x1301;
    s->group = 0x001D;
    s->state = TLS_STATE_ESTABLISHED;
    s->sessions_open = 2;
    s->stack_free = 3333;
    s->esp_time = 1790000000;
    s->time_source = TLS_TIME_NIOS;
    wifi_tls_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    r = wifi_tls_take_stats(reply.bytes, sizeof(rpc_tls_stats_resp), SEQUENCE, &stats, &esp_err);
    check((r == 0) && (stats.heap_free == 100001) && (stats.heap_min_ever == 90002) && (stats.largest_block == 50003) &&
          (stats.ct_in_bytes == 4) && (stats.ct_out_bytes == 5) && (stats.pt_in_bytes == 6) &&
          (stats.pt_out_bytes == 7) && (stats.handshake_us == 456789) && (stats.tls_version == 0x0304) &&
          (stats.ciphersuite == 0x1301) && (stats.group == 0x001D) && (stats.state == WIFI_TLS_ESTABLISHED) &&
          (stats.sessions_open == 2) && (stats.stack_free == 3333) && (stats.esp_time == 1790000000) &&
          (stats.time_source == WIFI_TLS_TIME_NIOS),
          "STATS: every field of the 60 bytes arrives");
    const int wrong[] = { 8, 48, 52, 56, 57, 59, 61, 64 };
    int refused_sizes = 0;
    for (unsigned k = 0; k < sizeof(wrong) / sizeof(wrong[0]); k++) {
        memset(&stats, 0, sizeof(stats));
        r = wifi_tls_take_stats(reply.bytes, wrong[k], SEQUENCE, &stats, &esp_err);
        refused_sizes += (r == WIFI_TLS_INVALID) && (stats.heap_free == 0);
    }
    check(refused_sizes == 8, "STATS: any size but 60, earlier layouts included, is invalid and nothing arrives");
}

// Answers to the TLS calls, from what the request asked.
static uint8_t maker_session = 1;
static uint8_t maker_state = TLS_STATE_ESTABLISHED;
static int maker_err = 0;
static uint16_t maker_ct = 5;
static uint16_t maker_pt = 4;

static void tls_maker(command_buf_t *rx, const uint8_t *req, int req_size, int kind)
{
    const rpc_header_t *request = (const rpc_header_t *)req;
    memset(rx->data, 0, sizeof(rx->data));
    rpc_header_t *hdr = (rpc_header_t *)rx->data;
    *hdr = *request;
    switch (request->command) {
        case CMD_TLS_OPEN:
            ((rpc_tls_open_resp *)rx->data)->esp_err = maker_err;
            ((rpc_tls_open_resp *)rx->data)->session = maker_err ? TLS_SESSION_GLOBAL : maker_session;
            ((rpc_tls_open_resp *)rx->data)->reason = maker_err ? TLS_OPEN_REASON_NO_TIME : 0;
            rx->size = sizeof(rpc_tls_open_resp);
            break;
        case CMD_TLS_STEP: {
            rpc_tls_step_resp *r = (rpc_tls_step_resp *)rx->data;
            r->esp_err = maker_err;
            r->state = maker_state;
            r->ct_out_len = maker_ct;
            r->pt_out_len = maker_pt;
            for (int i = 0; i < maker_ct + maker_pt; i++) {
                r->data[i] = (uint8_t)(i + 1);
            }
            rx->size = offsetof(rpc_tls_step_resp, data) + maker_ct + maker_pt;
            break;
        }
        case CMD_TLS_STATS:
            ((rpc_tls_stats_resp *)rx->data)->heap_free = 123456;
            rx->size = sizeof(rpc_tls_stats_resp);
            break;
        default:
            ((rpc_espcmd_resp *)rx->data)->esp_err = maker_err;
            rx->size = sizeof(rpc_espcmd_resp);
            break;
    }
}

// The request that went out, as the world recorded it: "transmit n: xx xx ...".
static std::string sent(void)
{
    size_t at = world_trace.find("transmit ");
    if (at == std::string::npos) {
        return "";
    }
    size_t end = world_trace.find('\n', at);
    return world_trace.substr(at, end - at);
}

static std::string hex(const uint8_t *bytes, int n)
{
    std::string out;
    char b[4];
    for (int i = 0; i < n; i++) {
        snprintf(b, sizeof(b), " %02x", bytes[i]);
        out += b;
    }
    return out;
}

static void test_calls(void)
{
    printf("The TLS calls through the channel\n");
    uint8_t session = 0x77;
    int esp_err = 0x55;
    uint8_t reason = 0x55;

    world_reset(1, tls_maker, true);
    uint16_t seq = sequence_nr;
    int r = wifi_tls_open(WIFI_TLS_FLAG_VERIFY | WIFI_TLS_FLAG_TEST_CA, "test.local", 0x6789ABCD, &session, &esp_err,
                          &reason);
    uint8_t expect[] = { CMD_TLS_OPEN, WIFI_DEDICATED_THREAD, (uint8_t)seq, (uint8_t)(seq >> 8), 0x05, 10, 0, 0,
                         0xCD, 0xAB, 0x89, 0x67, 't', 'e', 's', 't', '.', 'l', 'o', 'c', 'a', 'l' };
    check((r == 0) && (session == 1) && (esp_err == 0) && (reason == 0) &&
          (sent() == "transmit 22:" + hex(expect, sizeof(expect))),
          "OPEN sends header, flags, length, zero padding, unix_time and name, and gives the session");

    world_reset(2, tls_maker, true);
    seq = sequence_nr;
    r = wifi_tls_open(0, NULL, 0, &session, &esp_err, &reason);
    uint8_t expect_nosni[] = { CMD_TLS_OPEN, WIFI_DEDICATED_THREAD, (uint8_t)seq, (uint8_t)(seq >> 8), 0, 0, 0, 0,
                               0, 0, 0, 0 };
    check((r == 0) && (sent() == "transmit 12:" + hex(expect_nosni, sizeof(expect_nosni))),
          "OPEN without a name or a time");

    char name[WIFI_TLS_MAX_SNI + 2];
    memset(name, 'a', sizeof(name));
    name[WIFI_TLS_MAX_SNI + 1] = 0;
    world_reset(3, tls_maker, true);
    esp_err = 0x55;
    r = wifi_tls_open(0, name, 0, &session, &esp_err, &reason);
    check((r == WIFI_TLS_TOO_LONG) && (world_trace.find("getbuffer") == std::string::npos) && (esp_err == 0),
          "OPEN with a 254 byte name sends nothing");
    name[WIFI_TLS_MAX_SNI] = 0;
    world_reset(4, tls_maker, true);
    r = wifi_tls_open(0, name, 0, &session, &esp_err, &reason);
    check((r == 0) && (world_transmits == 1) && (sent().compare(0, 14, "transmit 265: ") == 0),
          "OPEN with a 253 byte name goes out");

    maker_err = 0x103;
    world_reset(5, tls_maker, true);
    session = 0x77;
    r = wifi_tls_open(0, "x", 0, &session, &esp_err, &reason);
    check((r == WIFI_TLS_REFUSED) && (esp_err == 0x103) && (session == 0x77) && (reason == TLS_OPEN_REASON_NO_TIME) &&
          (world_trace.find("print: TLS Open failed (2). Size: 12. Error: 259.") != std::string::npos),
          "OPEN refused: the error comes back and is logged, no session");
    maker_err = 0;

    wifi_tls_step_t st;
    uint8_t ct_in[3] = { 0xA1, 0xA2, 0xA3 };
    uint8_t pt_in[2] = { 0xB1, 0xB2 };
    fresh_step(&st, 1024);
    st.ct_in = ct_in;
    st.ct_in_len = 3;
    st.pt_in = pt_in;
    st.pt_in_len = 2;
    world_reset(6, tls_maker, true);
    seq = sequence_nr;
    r = wifi_tls_step(7, &st);
    uint8_t expect_step[] = { CMD_TLS_STEP, WIFI_DEDICATED_THREAD, (uint8_t)seq, (uint8_t)(seq >> 8), 7, 0, 3, 0, 2, 0,
                              0xA1, 0xA2, 0xA3, 0xB1, 0xB2 };
    check((r == 0) && (sent() == "transmit 15:" + hex(expect_step, sizeof(expect_step))) && (st.ct_out_len == 5) &&
          (st.pt_out_len == 4) && (ct_out[0] == 1) && (ct_out[4] == 5) && (pt_out[0] == 6) && (pt_out[3] == 9) &&
          (st.state == WIFI_TLS_ESTABLISHED),
          "STEP sends session, lengths, ciphertext then plaintext, and splits the answer the same way");

    static uint8_t big[WIFI_TLS_STEP_MAX_IN + 1];
    fresh_step(&st, 1024);
    st.ct_in = big;
    st.ct_in_len = 1000;
    st.pt_in = big;
    st.pt_in_len = 537;
    world_reset(7, tls_maker, true);
    r = wifi_tls_step(7, &st);
    check((r == WIFI_TLS_TOO_LONG) && (world_trace.find("getbuffer") == std::string::npos) && (st.ct_out_len == 0) &&
          (st.pt_out_len == 0) && (st.state == WIFI_TLS_UNKNOWN) && untouched(ct_out),
          "STEP with 1537 bytes in sends nothing and hands out nothing");
    st.pt_in_len = 536;
    world_reset(8, tls_maker, true);
    r = wifi_tls_step(7, &st);
    check((r == 0) && (world_transmits == 1) && (sent().compare(0, 15, "transmit 1546: ") == 0),
          "STEP with exactly 1536 bytes in goes out in one request");

    world_reset(9, tls_maker, true);
    r = wifi_tls_close(7, &esp_err);
    uint16_t seq9 = sequence_nr - 1;
    uint8_t expect_close[] = { CMD_TLS_CLOSE, WIFI_DEDICATED_THREAD, (uint8_t)seq9, (uint8_t)(seq9 >> 8), 7, 0 };
    check((r == 0) && (sent() == "transmit 6:" + hex(expect_close, sizeof(expect_close))), "CLOSE sends the session, and a zero, not an old byte, as padding");

    wifi_tls_stats_t stats;
    world_reset(10, tls_maker, true);
    r = wifi_tls_stats(WIFI_TLS_SESSION_GLOBAL, &stats, &esp_err);
    check((r == 0) && (stats.heap_free == 123456) && (world_trace.find(" 33 0c ") != std::string::npos),
          "STATS for the module as a whole");

    // The shared channel.
    world_reset(11, tls_maker, true);
    dedicated_waiting = true; // GET_RANDOM, say, is waiting
    r = wifi_tls_close(7, &esp_err);
    check((r == WIFI_TLS_UNSENT) && (world_transmits == 0) && dedicated_waiting &&
          (world_trace.find("no reply") == std::string::npos),
          "while another request is outstanding a call fails at once as unsent, and leaves the channel to its owner");
    world_reset(16, tls_maker, true);
    world_no_buffer = true;
    r = wifi_tls_close(7, &esp_err);
    check((r == WIFI_TLS_UNSENT) && (world_transmits == 0) && !dedicated_waiting,
          "without a transmit buffer a call is unsent, not busy, and frees the channel");
    world_reset(17, tls_maker, true);
    world_no_transmit = true;
    r = wifi_tls_step(7, &st);
    check((r == WIFI_TLS_UNSENT) && (world_transmits == 0) && !dedicated_waiting && (st.ct_out_len == 0),
          "a transmit that fails is unsent, not busy, and frees the channel");
    world_reset(12, tls_maker, true);
    world_ready = false;
    r = wifi_tls_close(7, &esp_err);
    check((r == WIFI_TLS_NO_MODULE) && (world_trace.empty()), "without the module application nothing is tried");

    // No answer: BUSY, and the wait is the call's own.
    world_reset(13, tls_maker, true);
    maker_session = 2;
    {
        // A world where the answer never comes: calm, but the maker answers another sequence.
        struct local {
            static void late(command_buf_t *rx, const uint8_t *req, int req_size, int kind)
            {
                tls_maker(rx, req, req_size, kind);
                ((rpc_header_t *)rx->data)->sequence++;
            }
        };
        world_reset(13, local::late, true);
        r = wifi_tls_step(7, &st);
        size_t waited = world_trace.find("receive 1000");
        check((r == WIFI_TLS_BUSY) && (waited != std::string::npos) &&
              (world_trace.find("print: TLS Step: no reply.") != std::string::npos) && !dedicated_waiting,
              "a step that gets no answer is busy after its own 5 s (1000 ticks), and frees the channel");
        world_reset(14, local::late, true);
        r = wifi_tls_open(0, "x", 0, &session, &esp_err, &reason);
        check((r == WIFI_TLS_BUSY) && (world_trace.find("receive 1000") != std::string::npos), "OPEN waits 5 s");
        world_reset(15, local::late, true);
        r = wifi_tls_stats(0, &stats, &esp_err);
        check((r == WIFI_TLS_BUSY) && (world_trace.find("receive 200") != std::string::npos), "STATS waits 1 s");
    }
    maker_session = 1;
}

int main(void)
{
    test_dedicated();
    test_take_step();
    test_take_others();
    test_calls();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
