/*
 * nios_pump.c
 *
 * Plays the Ultimate against the ESP32's TLS engine on the host: the real
 * rpc_dispatch.c handlers and tls_engine.c, with mbedTLS built on the host,
 * and a TCP socket to a real TLS 1.3 server. The loops follow spike_run() in
 * software/io/wifi/wifi_tls_spike.cc: the same step sizes, the same resends,
 * the same waits. One connection per run: it is a client as described in
 * software/test/tls_interop/interop.py, which runs the matrix.
 *
 *   nios_pump --list
 *   nios_pump --port N --sni NAME [--verify 0|1] [--echo BYTES] [--push BYTES]
 *             [--pt-chunk BYTES] [--ct-chunk BYTES] [--after none|close|eof] [--seed N] [--baud N]
 *             [--settle-ms MS] [--settle-at STEP] [--ct-caps N,N,...] [--split SEED]
 *
 * --echo: send that many bytes in steps of --pt-chunk and read the same back.
 * --push: send nothing, read that many bytes the server sends on its own.
 * --ct-chunk: take at most this much ciphertext from the socket per step
 *   (0: as much as the step has room for, as the Nios does).
 * --baud: each step takes as long as its request and reply take on a serial link
 *   this fast (default 5000000, wifi_cmd.cc's lower rate; 0: no delay). The
 *   server's next flight then meets the steps where it meets them on the rig:
 *   NewSessionTickets land among the echo steps, not after them.
 * --settle-ms: wait this long before echo step --settle-at (default 0: before
 *   the first), so that all the server has sent by then is in the socket.
 * --ct-caps: the ciphertext the first echo steps take, at most, one number a
 *   step (0: none, even if some has come). With --settle-ms it scripts how the
 *   server's flight lands in the steps.
 * --split: cut what arrives from the server at pseudo-random points from SEED
 *   (arbitrary TCP segmentation, reproducible).
 * --after close: then step until the server's close_notify ends the session.
 * --after eof: then step until the server closes the TCP connection.
 *
 * --list: the TLS 1.3 cipher suites and the groups, in the order the client
 *   offers them, of the mbedTLS this was built with and the engine's preset.
 *
 * Every step is logged as a STEP line. The last line is "RESULT key=value ...". The engine's own claims (version,
 * suite) are printed as engine_*, for information only.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "esp_stub_all.h"
#include "cmd_buffer.h"
#include "rpc_calls.h"
#include "tls_engine.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/build_info.h"

void cmd_tls_open(command_buf_t *buf);
void cmd_tls_step(command_buf_t *buf);
void cmd_tls_close(command_buf_t *buf);
void cmd_tls_stats(command_buf_t *buf);

#define ECHO_CHUNK   512   // wifi_tls_spike.cc: plaintext per step
#define TIMEOUT_MS   15000 // wifi_tls_spike.cc: HANDSHAKE_TIMEOUT_MS and ECHO_TIMEOUT_MS

/* ---- ESP-IDF stand-ins: what tls_engine.c and the four handlers call ---- */
entropy_source_t entropy_source(void) { return ENTROPY_RADIO; }
int sntp_has_time(void) { return 0; }
static int transmitted;
BaseType_t my_uart_transmit_packet(uint8_t u, command_buf_t *b) { transmitted++; return pdTRUE; }
int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000LL + t.tv_nsec / 1000;
}
size_t heap_caps_get_free_size(uint32_t c) { return 0; }
size_t heap_caps_get_minimum_free_size(uint32_t c) { return 0; }
size_t heap_caps_get_largest_free_block(uint32_t c) { return 0; }
esp_err_t heap_caps_monitor_local_minimum_free_size_start(void) { return ESP_OK; }
esp_err_t heap_caps_monitor_local_minimum_free_size_stop(void) { return ESP_OK; }
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t t) { return 0; }
esp_err_t esp_crt_bundle_attach(void *conf) { return ESP_ERR_NOT_SUPPORTED; }
QueueHandle_t connect_commands; // data the other handlers in rpc_dispatch.c name
SemaphoreHandle_t connect_semaphore;
esp_netif_t *my_sta_netif;
// tls_engine.c is built with -Dsettimeofday=harness_settimeofday: the host clock is already right
int harness_settimeofday(const struct timeval *tv, const void *tz) { return 0; }

/* ---- the RPCs, as the Ultimate sends them ---- */
static command_buf_t B;
static uint16_t seq;
static long baud = 5000000;

// 10 bits a byte on the UART, SLIP's two frame ends, escapes left out
static void link_delay(int bytes)
{
    if (baud > 0) {
        long ns = (long)((bytes + 2) * 10 * 1000000000LL / baud);
        struct timespec t = { ns / 1000000000L, ns % 1000000000L };
        nanosleep(&t, NULL);
    }
}

// The request is built in B.data, after the header, as the Ultimate's command buffer holds it
static void request(uint8_t cmd, int len)
{
    rpc_header_t *h = (rpc_header_t *)B.data;
    h->command = cmd;
    h->thread = 0x0D;
    h->sequence = ++seq;
    B.size = len;
    link_delay(len);
    int before = transmitted;
    switch (cmd) {
    case CMD_TLS_OPEN: cmd_tls_open(&B); break;
    case CMD_TLS_STEP: cmd_tls_step(&B); break;
    case CMD_TLS_CLOSE: cmd_tls_close(&B); break;
    case CMD_TLS_STATS: cmd_tls_stats(&B); break;
    }
    link_delay(B.size);
    if ((transmitted != before + 1) || (h->command != cmd) || (h->sequence != seq)) {
        printf("RESULT outcome=HARNESS_ERROR detail=reply_header\n");
        exit(3);
    }
}

typedef struct {
    int esp_err;
    uint8_t state;
    int ct_out_len;
    int pt_out_len;
    const uint8_t *ct_out;
    const uint8_t *pt_out;
} step_t;

static step_t step(uint8_t session, const uint8_t *ct, int ct_len, const uint8_t *pt, int pt_len)
{
    rpc_tls_step_req *req = (rpc_tls_step_req *)B.data;
    memset(B.data, 0xEE, sizeof(B.data));
    memset(&req->session, 0, sizeof(rpc_tls_step_req) - sizeof(rpc_header_t));
    req->session = session;
    req->ct_in_len = ct_len;
    req->pt_in_len = pt_len;
    memcpy(req->data, ct, ct_len);
    memcpy(req->data + ct_len, pt, pt_len);
    request(CMD_TLS_STEP, sizeof(rpc_tls_step_req) + ct_len + pt_len);
    rpc_tls_step_resp *r = (rpc_tls_step_resp *)B.data;
    step_t s = { r->esp_err, r->state, r->ct_out_len, r->pt_out_len, r->data, r->data + r->ct_out_len };
    printf("STEP ct_in=%d pt_in=%d -> esp_err=%s0x%04x state=%d ct_out=%d pt_out=%d\n", ct_len, pt_len,
           (s.esp_err < 0) ? "-" : "", (unsigned)abs(s.esp_err), s.state, s.ct_out_len, s.pt_out_len);
    if ((B.size != (int)sizeof(rpc_tls_step_resp) + s.ct_out_len + s.pt_out_len) ||
        (s.ct_out_len + s.pt_out_len > TLS_STEP_OUT_MAX)) {
        printf("RESULT outcome=HARNESS_ERROR detail=step_reply_size\n");
        exit(3);
    }
    return s;
}

static void session_request(uint8_t cmd, uint8_t session)
{
    rpc_tls_session_req *req = (rpc_tls_session_req *)B.data;
    memset(B.data, 0xEE, sizeof(B.data));
    req->session = session;
    req->reserved = 0;
    request(cmd, sizeof(rpc_tls_session_req));
}

/* ---- the run ---- */
static struct {
    const char *stage;
    int esp_err;
    int state;
    int steps, resends;
    long pt_delivered; // plaintext the engine handed out, in any stage
    long echo_sent, echo_received;
    int echo_ok;
    int tcp_eof;
    long tcp_in, tcp_out;
} R = { .stage = "open", .state = -1 };

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }
static uint32_t seed;
static uint8_t payload(long i) { return (uint8_t)((i * 131 + (i >> 8) * 7 + seed) ^ (seed >> 8)); }

static long expect;

static void finish(const char *outcome, const char *detail)
{
    R.echo_ok = expect && (R.echo_received == expect); // every byte was compared as it came
    printf("RESULT outcome=%s stage=%s detail=%s esp_err=%s0x%04x state=%d steps=%d resends=%d pt_delivered=%ld "
           "echo_sent=%ld echo_received=%ld echo_ok=%d tcp_in=%ld tcp_out=%ld tcp_eof=%d sessions_open=%d\n",
           outcome, R.stage, detail, (R.esp_err < 0) ? "-" : "", (unsigned)abs(R.esp_err), R.state, R.steps,
           R.resends, R.pt_delivered, R.echo_sent, R.echo_received, R.echo_ok, R.tcp_in, R.tcp_out, R.tcp_eof,
           tls_sessions_open());
    fflush(stdout);
    exit(0);
}

static void send_all(int fd, const uint8_t *data, int len)
{
    while (len > 0) {
        ssize_t n = send(fd, data, len, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            R.tcp_eof = 1;
            return; // the Nios fails the send; here the next receive or step says why
        }
        R.tcp_out += n;
        data += n;
        len -= n;
    }
}

// With --split, what the socket gave is held here and handed out in pieces
static uint8_t held[1 << 16];
static int held_len, held_eof;
static uint32_t split_state;

static uint32_t split_next(void)
{
    split_state = split_state * 1103515245u + 12345u;
    return split_state >> 8;
}

// wifi_tls_spike.cc receive(): at once when wait is false, else until the deadline. -1 at EOF.
static int socket_receive(int fd, uint8_t *buf, int room, int wait, int64_t start)
{
    for (;;) {
        struct pollfd pf = { fd, POLLIN, 0 };
        int ready = poll(&pf, 1, wait ? 50 : 0);
        if (ready > 0) {
            ssize_t n = recv(fd, buf, room, 0);
            if (n > 0) {
                R.tcp_in += n;
                return (int)n;
            }
            if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
                R.tcp_eof = 1;
                return -1;
            }
        }
        if (!wait) {
            return 0;
        }
        if (now_ms() - start > TIMEOUT_MS) {
            finish("TIMEOUT", "no data from the server");
        }
    }
}

// --split: the bytes that have arrived come out cut at pseudo-random points, as TCP may cut
// them, and sometimes not at all yet (never when the Nios would wait). Same seed, same cuts.
static int receive(int fd, uint8_t *buf, int room, int wait, int64_t start)
{
    if (!split_state) {
        return socket_receive(fd, buf, room, wait, start);
    }
    for (;;) {
        if (!held_eof && held_len < (int)sizeof(held)) {
            int n = socket_receive(fd, held + held_len, sizeof(held) - held_len, wait && !held_len, start);
            if (n < 0) {
                held_eof = 1;
            } else {
                held_len += n;
            }
        }
        if (held_len) {
            int n = (int)(split_next() % (room + 1));
            if (n > held_len) {
                n = held_len;
            }
            if (wait && !n) {
                n = 1;
            }
            memcpy(buf, held, n);
            memmove(held, held + n, held_len - n);
            held_len -= n;
            return n;
        }
        if (held_eof) {
            return -1;
        }
        if (!wait) {
            return 0;
        }
    }
}

static void failed_step(step_t s)
{
    R.esp_err = s.esp_err;
    R.state = s.state;
    finish((s.state == TLS_STATE_FAILED) ? "FAILED" : (s.state == TLS_STATE_CLOSED) ? "CLOSED" : "STEP_ERROR",
           "step");
}

// What the engine offers: tls_setup() takes mbedTLS's defaults for a TLS 1.3 client
static int list(void)
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    printf("SUITES");
    for (const int *id = mbedtls_ssl_list_ciphersuites(); *id; id++) {
        const mbedtls_ssl_ciphersuite_t *cs = mbedtls_ssl_ciphersuite_from_id(*id);
        if (cs && (cs->MBEDTLS_PRIVATE(max_tls_version) >= MBEDTLS_SSL_VERSION_TLS1_3) &&
            (cs->MBEDTLS_PRIVATE(min_tls_version) <= MBEDTLS_SSL_VERSION_TLS1_3)) {
            printf(" %s:0x%04x", cs->MBEDTLS_PRIVATE(name), *id);
        }
    }
    printf("\nGROUPS");
    for (const uint16_t *g = conf.MBEDTLS_PRIVATE(group_list); g && *g; g++) {
        printf(" 0x%04x", *g);
    }
    printf("\nINFO tls_engine.c through rpc_dispatch.c, %s, config %s\n", MBEDTLS_VERSION_STRING_FULL,
           MBEDTLS_CONFIG_FILE);
    mbedtls_ssl_config_free(&conf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        return list();
    }
    int port = 0, verify = 1, pt_chunk = ECHO_CHUNK, ct_chunk = 0, settle_ms = 0, settle_at = 0;
    int caps[32], n_caps = 0;
    long echo = 0, push = 0;
    const char *sni = "localhost", *after = "none";
    for (int i = 1; i + 1 < argc; i += 2) {
        const char *k = argv[i], *v = argv[i + 1];
        if (!strcmp(k, "--port")) port = atoi(v);
        else if (!strcmp(k, "--sni")) sni = v;
        else if (!strcmp(k, "--verify")) verify = atoi(v);
        else if (!strcmp(k, "--echo")) echo = atol(v);
        else if (!strcmp(k, "--push")) push = atol(v);
        else if (!strcmp(k, "--pt-chunk")) pt_chunk = atoi(v);
        else if (!strcmp(k, "--ct-chunk")) ct_chunk = atoi(v);
        else if (!strcmp(k, "--after")) after = v;
        else if (!strcmp(k, "--seed")) seed = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(k, "--baud")) baud = atol(v);
        else if (!strcmp(k, "--settle-ms")) settle_ms = atoi(v);
        else if (!strcmp(k, "--settle-at")) settle_at = atoi(v);
        else if (!strcmp(k, "--ct-caps")) {
            for (char *e, *c = (char *)v; *c && n_caps < 32; c = (*e == ',') ? e + 1 : e) {
                caps[n_caps++] = (int)strtol(c, &e, 0);
                if (e == c) {
                    break;
                }
            }
        }
        else if (!strcmp(k, "--split")) split_state = (uint32_t)strtoul(v, NULL, 0);
        else { fprintf(stderr, "unknown option %s\n", k); return 2; }
    }
    if (!port || pt_chunk <= 0 || pt_chunk >= TLS_STEP_IN_MAX) {
        fprintf(stderr, "usage: see nios_pump.c\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        finish("CONNECT_FAILED", strerror(errno));
    }

    // CMD_TLS_OPEN with the Ultimate's clock
    rpc_tls_open_req *o = (rpc_tls_open_req *)B.data;
    memset(B.data, 0xEE, sizeof(B.data));
    memset(&o->flags, 0, sizeof(rpc_tls_open_req) - sizeof(rpc_header_t));
    o->flags = verify ? (TLS_OPEN_VERIFY | TLS_OPEN_CA_TEST) : 0;
    o->sni_len = (uint8_t)strlen(sni);
    o->unix_time = (uint32_t)time(NULL);
    memcpy(o->sni, sni, o->sni_len);
    request(CMD_TLS_OPEN, sizeof(rpc_tls_open_req) + o->sni_len);
    rpc_tls_open_resp *or = (rpc_tls_open_resp *)B.data;
    if (or->esp_err != ESP_OK) {
        R.esp_err = or->esp_err;
        finish("OPEN_FAILED", "open");
    }
    uint8_t session = or->session;

    uint8_t in[TLS_STEP_IN_MAX], pt_in[TLS_STEP_IN_MAX];
    int in_room = TLS_STEP_IN_MAX;
    if (ct_chunk && ct_chunk < in_room) {
        in_room = ct_chunk;
    }

    // wifi_tls_spike.cc reads the session's STATS before the handshake and again after it
    session_request(CMD_TLS_STATS, session);

    // The handshake: a step answered NO_MEM goes again as it is
    R.stage = "handshake";
    int64_t start = now_ms();
    int in_len = 0;
    for (;;) {
        step_t s = step(session, in, in_len, NULL, 0);
        R.steps++;
        int resend = (s.esp_err == ESP_ERR_NO_MEM);
        if (resend) {
            R.resends++;
        } else if (s.esp_err != ESP_OK) {
            send_all(fd, s.ct_out, s.ct_out_len); // the alert of a failed handshake goes to the server too
            failed_step(s);
        } else {
            in_len = 0;
        }
        send_all(fd, s.ct_out, s.ct_out_len);
        R.pt_delivered += s.pt_out_len;
        R.state = s.state;
        if (s.state == TLS_STATE_ESTABLISHED) {
            if (!resend) {
                break;
            }
        } else if (s.state != TLS_STATE_HANDSHAKING) {
            failed_step(s);
        }
        if (!resend) {
            int more = s.ct_out_len || s.pt_out_len;
            in_len = receive(fd, in, in_room, !more, start);
            if (in_len < 0) {
                finish("PEER_CLOSED", "handshake_recv");
            }
        }
        if (now_ms() - start > TIMEOUT_MS) {
            finish("TIMEOUT", "handshake");
        }
    }

    session_request(CMD_TLS_STATS, session);
    // The echo (or the push): plaintext out in chunks, the same bytes back
    R.stage = echo ? "echo" : "push";
    expect = echo ? echo : push;
    start = now_ms();
    int more = 0, resend = 0, chunk = 0, echo_steps = 0;
    in_len = 0;
    while (R.echo_received < expect) {
        if (settle_ms && (echo_steps == settle_at)) {
            struct timespec t = { settle_ms / 1000, (settle_ms % 1000) * 1000000L };
            nanosleep(&t, NULL);
        }
        if (!resend) {
            chunk = (int)(echo - R.echo_sent);
            if (chunk > pt_chunk) {
                chunk = pt_chunk;
            }
            for (int i = 0; i < chunk; i++) {
                pt_in[i] = payload(R.echo_sent + i);
            }
            int wait = (chunk == 0) && !more;
            int room = TLS_STEP_IN_MAX - chunk;
            if (in_room < room) {
                room = in_room;
            }
            if ((echo_steps < n_caps) && (caps[echo_steps] < room)) {
                room = caps[echo_steps];
            }
            in_len = room ? receive(fd, in, room, wait, start) : 0;
            if (in_len < 0) {
                finish("PEER_CLOSED", "echo_recv");
            }
        }
        step_t s = step(session, in, in_len, pt_in, chunk);
        R.steps++;
        echo_steps++;
        resend = (s.esp_err == ESP_ERR_NO_MEM);
        if (resend) {
            R.resends++;
        } else if (s.esp_err == ESP_OK) {
            R.echo_sent += chunk;
        }
        // A failing step still hands out what came before the failure: it is checked like the rest
        send_all(fd, s.ct_out, s.ct_out_len);
        R.pt_delivered += s.pt_out_len;
        for (int i = 0; i < s.pt_out_len; i++) {
            if ((R.echo_received + i >= expect) || (s.pt_out[i] != payload(R.echo_received + i))) {
                R.echo_received += i;
                R.state = s.state;
                finish("ECHO_MISMATCH", "echo_compare");
            }
        }
        R.echo_received += s.pt_out_len;
        R.state = s.state;
        if (!resend && (s.esp_err != ESP_OK)) {
            failed_step(s);
        }
        if (s.state != TLS_STATE_ESTABLISHED) {
            R.esp_err = s.esp_err;
            finish((s.state == TLS_STATE_CLOSED) ? "CLOSED" : "FAILED", "echo_state");
        }
        more = s.ct_out_len || s.pt_out_len;
        if (now_ms() - start > TIMEOUT_MS) {
            finish("TIMEOUT", "echo");
        }
    }

    // What the server does next: close_notify, or a bare TCP close
    if (!strcmp(after, "close") || !strcmp(after, "eof")) {
        R.stage = "after";
        start = now_ms();
        more = 0;
        for (;;) {
            in_len = receive(fd, in, in_room, !more, start);
            if (in_len < 0) {
                finish("PEER_CLOSED", "after_recv");
            }
            step_t s = step(session, in, in_len, NULL, 0);
            R.steps++;
            send_all(fd, s.ct_out, s.ct_out_len);
            R.pt_delivered += s.pt_out_len;
            R.state = s.state;
            R.esp_err = s.esp_err;
            if (s.pt_out_len) {
                finish("UNEXPECTED_DATA", "after");
            }
            if (s.state != TLS_STATE_ESTABLISHED) {
                finish((s.state == TLS_STATE_CLOSED) ? "CLOSED" : "FAILED", "after_state");
            }
            more = s.ct_out_len != 0;
        }
    }

    // The engine's own view, for the log only
    session_request(CMD_TLS_STATS, session);
    rpc_tls_stats_resp *st = (rpc_tls_stats_resp *)B.data;
    printf("engine_version=0x%04x engine_suite=0x%04x engine_pt_in=%u engine_pt_out=%u\n", st->tls_version,
           st->ciphersuite, st->pt_in_bytes, st->pt_out_bytes);
    session_request(CMD_TLS_CLOSE, session);
    close(fd);
    finish("ECHO_OK", "done");
}
