/*
 * engine_test.c
 *
 * Host test of the ESP32 TLS engine and its RPC handlers (M3-SPEC v1 section 5). It plays the Ultimate:
 * it builds every request byte by byte at the offsets the spec freezes (never from rpc_calls.h, so a
 * layout slip on the ESP32 side fails here), runs the real rpc_dispatch.c and tls_engine.c against
 * mbedTLS 4.1.1 built with the ESP32's configuration, and moves the ciphertext to a local server (m3srv).
 *
 *   engine_test [CASE...]      runs every case (or the named ones), each in its own process
 * Environment: M3SRV (server binary), PKI (mkpki.sh output), LOGDIR, PORTBASE.
 * BASE_ENGINE builds it against the M2 engine (a846369f), where the TLS task and CLOSE_ALL/SET_CA do not exist:
 * that build is how the RED runs are made.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "esp_stub_all.h"
#include "cmd_buffer.h"
#include "mbedtls/platform_time.h"
#include "psa/crypto.h"

/* ---- wire constants, from M3-SPEC v1 section 5.2 (not from rpc_calls.h) ---- */
enum { OPEN = 0x30, STEP = 0x31, CLOSE = 0x32, STATS = 0x33, CLOSE_ALL = 0x34, SET_CA = 0x35 };
enum { BUNDLE = 0, CUSTOM = 1, PIN = 2 };
enum { HANDSHAKING = 0, ESTABLISHED = 1, CLOSED = 2, FAILED = 3 };
enum { R_NONE = 0, R_VERSION = 1, R_DOWNGRADE = 2, R_NO_EMS = 3, R_CERT = 4, R_PIN = 5, R_PEER_CLOSED = 6 };
#define REQUIRE_TLS13 0x01
#define NO_READ 0x01
#define E_NO_MEM 0x101
#define E_INVALID_ARG 0x102
#define E_INVALID_STATE 0x103
#define E_NOT_FOUND 0x105
#define E_NOT_SUPPORTED 0x106
#define E_TIMEOUT 0x107
#define SEED_SERVER 7
#define SEED_CLIENT 11
static uint8_t pattern(long i, int seed) { return (uint8_t)(i * 31 + seed); }

/* ---- the code under test ---- */
void cmd_tls_open(command_buf_t *buf);
void cmd_tls_step(command_buf_t *buf);
void cmd_tls_close(command_buf_t *buf);
void cmd_tls_stats(command_buf_t *buf);
void start_dispatch(QueueHandle_t queue);
#ifndef BASE_ENGINE
void dispatch_command(command_buf_t *buf);
void tls_serve(command_buf_t *buf);
#endif

/* ---- checks ---- */
static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- ESP-IDF stand-ins ---- */
enum { ENTROPY_NONE = 0, ENTROPY_RADIO = 1 }; // entropy_source_t (rpc_calls.h, GET_RANDOM)
static int entropy = ENTROPY_RADIO;
int entropy_source(void) { return entropy; }
static int sntp_flag;
int sntp_has_time(void) { return sntp_flag; }
void sntp_get_time(const char *tz, void *dt) { (void)tz; (void)dt; }
static int transmitted;
static command_buf_t *last_tx;
BaseType_t my_uart_transmit_packet(uint8_t u, command_buf_t *b) { (void)u; transmitted++; last_tx = b; return pdTRUE; }
BaseType_t my_uart_free_buffer(uint8_t u, command_buf_t *b) { (void)u; (void)b; return pdTRUE; }
static command_buf_t spare;
BaseType_t my_uart_get_buffer(uint8_t u, command_buf_t **b, TickType_t t) { (void)u; (void)t; *b = &spare; return pdTRUE; }
static int64_t timer_offset_us;
int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000LL + t.tv_nsec / 1000 + timer_offset_us;
}
void vTaskDelay(TickType_t t) { timer_offset_us += (int64_t)t * 1000; } /* a blocked dispatcher, without the wait */
size_t heap_caps_get_free_size(uint32_t c) { (void)c; return 111111; }
size_t heap_caps_get_minimum_free_size(uint32_t c) { (void)c; return 99999; }
size_t heap_caps_get_largest_free_block(uint32_t c) { (void)c; return 55555; }
esp_err_t heap_caps_monitor_local_minimum_free_size_start(void) { return ESP_OK; }
esp_err_t heap_caps_monitor_local_minimum_free_size_stop(void) { return ESP_OK; }
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t t) { (void)t; return 4321; }
void esp_fill_random(void *buf, size_t len) { arc4random_buf(buf, len); }
esp_err_t esp_wifi_get_mac(wifi_interface_t i, uint8_t mac[6]) { (void)i; memset(mac, 0, 6); return ESP_OK; }
esp_err_t esp_wifi_disconnect(void) { return ESP_OK; }
esp_err_t uart_set_baudrate(int n, uint32_t b) { (void)n; (void)b; return ESP_OK; }
esp_err_t uart_set_hw_flow_ctrl(int n, int f, uint8_t t) { (void)n; (void)f; (void)t; return ESP_OK; }
esp_err_t uart_set_line_inverse(int n, uint32_t m) { (void)n; (void)m; return ESP_OK; }
esp_err_t gpio_set_level(int g, uint32_t l) { (void)g; (void)l; return ESP_OK; }
esp_err_t esp_netif_transmit(esp_netif_t *n, void *d, size_t l) { (void)n; (void)d; (void)l; return ESP_OK; }
void wifi_note_user_disconnect(void) {}
uint8_t wifi_get_connection(void) { return 0; }
esp_err_t wifi_clear_aps(void) { return ESP_OK; }
void enable_hook(void) {}
void disable_hook(void) {}
QueueHandle_t connect_commands;
SemaphoreHandle_t connect_semaphore;
esp_netif_t *my_sta_netif;
BaseType_t xSemaphoreGive(SemaphoreHandle_t s) { (void)s; return pdTRUE; }

/* FreeRTOS queues as plain FIFOs, and tasks that are recorded, not run */
typedef struct { int cap, size, n, head; uint8_t items[16][16]; } fake_queue_t;
static fake_queue_t queues[8];
static int nqueues;
QueueHandle_t xQueueCreate(UBaseType_t n, UBaseType_t size)
{
    fake_queue_t *q = &queues[nqueues++];
    q->cap = (int)n; q->size = (int)size; q->n = 0; q->head = 0;
    return q;
}
BaseType_t xQueueSend(QueueHandle_t h, const void *item, TickType_t t)
{
    (void)t;
    fake_queue_t *q = h;
    if (!q || q->n == q->cap) return pdFALSE;
    memcpy(q->items[(q->head + q->n++) % 16], item, q->size);
    return pdTRUE;
}
BaseType_t xQueueReceive(QueueHandle_t h, void *item, TickType_t t)
{
    (void)t;
    fake_queue_t *q = h;
    if (!q || q->n == 0) return pdFALSE;
    memcpy(item, q->items[q->head], q->size);
    q->head = (q->head + 1) % 16; q->n--;
    return pdTRUE;
}
typedef struct { char name[32]; uint32_t stack; void *arg; UBaseType_t prio; int core; } fake_task_t;
static fake_task_t tasks[8];
static int ntasks;
static BaseType_t record_task(const char *name, uint32_t stack, void *arg, UBaseType_t prio, TaskHandle_t *h, int core)
{
    fake_task_t *t = &tasks[ntasks++];
    snprintf(t->name, sizeof(t->name), "%s", name);
    t->stack = stack; t->arg = arg; t->prio = prio; t->core = core;
    if (h) *h = t;
    return pdTRUE;
}
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, uint32_t stack, void *arg, UBaseType_t prio, TaskHandle_t *h)
{ (void)fn; return record_task(name, stack, arg, prio, h, -1); }
BaseType_t xTaskCreatePinnedToCore(void (*fn)(void *), const char *name, uint32_t stack, void *arg, UBaseType_t prio,
                                   TaskHandle_t *h, BaseType_t core)
{ (void)fn; return record_task(name, stack, arg, prio, h, (int)core); }
static fake_task_t *find_task(const char *name)
{
    for (int i = 0; i < ntasks; i++) if (!strcmp(tasks[i].name, name)) return &tasks[i];
    return NULL;
}

/* ESP-IDF 6's mbedTLS glue (esp_config.h: PLATFORM_STD_CALLOC, MS_TIME_ALT, PSA_CRYPTO_EXTERNAL_RNG) */
void *esp_mbedtls_mem_calloc(size_t n, size_t size) { return calloc(n, size); }
void esp_mbedtls_mem_free(void *p) { free(p); }
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (mbedtls_ms_time_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static long rng_draws;
psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *c, uint8_t *out, size_t n, size_t *len)
{
    (void)c;
    rng_draws++;
    arc4random_buf(out, n);
    *len = n;
    return PSA_SUCCESS;
}
/* One clock for the engine and for mbedTLS's validity checks: the executable's time() wins at link time */
static time_t fake_now;
time_t time(time_t *t) { if (t) *t = fake_now; return fake_now; }
int settimeofday(const struct timeval *tv, const struct timezone *tz) { (void)tz; fake_now = tv->tv_sec; return 0; }
static time_t real_now(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return ts.tv_sec; }

/* ---- the RPC channel ---- */
static command_buf_t B;
static uint16_t seq = 0x1000;
static int reply_size;

static void rd(int off, void *v, int n) { memcpy(v, B.data + off, n); }
static int32_t rd32(int off) { int32_t v; rd(off, &v, 4); return v; }
static uint16_t rd16(int off) { uint16_t v; rd(off, &v, 2); return v; }
static uint8_t rd8(int off) { return B.data[off]; }
static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static void put_request(uint8_t cmd, const void *payload, int len)
{
    memset(B.data, 0xEE, sizeof(B.data));
    B.data[0] = cmd; B.data[1] = 0x0D;
    ++seq;
    memcpy(B.data + 2, &seq, 2);
    if (len) memcpy(B.data + 4, payload, len);
    B.size = 4 + len;
}

static int is_tls(uint8_t cmd) { return cmd >= OPEN && cmd <= SET_CA; }

// Sends one request and returns the reply size; the reply is in B.data
static int rpc(uint8_t cmd, const void *payload, int len)
{
    put_request(cmd, payload, len);
    int before = transmitted;
#ifdef BASE_ENGINE
    switch (cmd) { // the M2 dispatcher's TLS cases; CLOSE_ALL and SET_CA did not exist (cmd_not_implemented)
    case OPEN: cmd_tls_open(&B); break;
    case STEP: cmd_tls_step(&B); break;
    case CLOSE: cmd_tls_close(&B); break;
    case STATS: cmd_tls_stats(&B); break;
    default: memset(B.data + 4, 0, 4); w32(B.data + 4, E_NOT_SUPPORTED); B.size = 8; transmitted++; last_tx = &B; break;
    }
#else
    dispatch_command(&B);
    if (is_tls(cmd)) {
        // The dispatcher only queues it; the TLS task runs it
        CHECK(transmitted == before, "cmd %02x: the dispatcher answers nothing itself", cmd);
        command_buf_t *q = NULL;
        CHECK(xQueueReceive(queues[nqueues - 1].cap == 2 ? &queues[nqueues - 1] : NULL, &q, 0) == pdTRUE && q == &B,
              "cmd %02x: queued for the TLS task", cmd);
        if (q) tls_serve(q);
    }
#endif
    CHECK(transmitted == before + 1, "cmd %02x: exactly one reply", cmd);
    CHECK(last_tx == &B && B.data[0] == cmd && B.data[1] == 0x0D && rd16(2) == seq, "cmd %02x: header echoed", cmd);
    reply_size = B.size;
    return B.size;
}

/* ---- request builders (offsets from 5.2; the payload starts after the 4-byte header) ---- */
static uint8_t g_time_source = 1;
static uint32_t g_unix_time;

typedef struct { int err; uint8_t slot, reason; } open_r;
static open_r tls_open2(uint8_t slot, uint16_t tag, uint8_t trust, uint8_t opts, uint16_t ca_tag, const uint8_t *pin,
                        const char *sni, int sni_len)
{
    uint8_t p[48 + 256] = { 0 };
    p[0] = trust; p[1] = (uint8_t)sni_len; p[2] = slot; p[3] = g_time_source;
    w32(p + 4, g_unix_time); w16(p + 8, tag); p[10] = opts; p[11] = 0; w16(p + 12, ca_tag); w16(p + 14, 0);
    if (pin) memcpy(p + 16, pin, 32); else memset(p + 16, 0x5A, 32);
    memcpy(p + 48, sni, sni_len);
    rpc(OPEN, p, 48 + sni_len);
    open_r r = { rd32(4), rd8(8), rd8(9) };
    CHECK(reply_size == 12, "open reply size %d", reply_size);
    CHECK(rd8(10) == 0 && rd8(11) == 0, "open reply padding zeroed");
    CHECK((r.reason != 0) == (r.err == E_INVALID_STATE), "open: reason exactly with INVALID_STATE (err %x reason %d)", r.err, r.reason);
    return r;
}
static open_r tls_open(uint8_t slot, uint16_t tag, uint8_t trust, uint8_t opts, uint16_t ca_tag, const uint8_t *pin, const char *sni)
{
    return tls_open2(slot, tag, trust, opts, ca_tag, pin, sni, (int)strlen(sni));
}

typedef struct {
    int err; uint8_t state, alert_in, alert_out, fail_reason; uint32_t verify_flags;
    uint16_t ct_len, pt_len; uint8_t data[CMD_BUF_SIZE];
} step_r;
static step_r last;

static step_r *tls_step(uint8_t slot, uint16_t tag, uint8_t flags, const uint8_t *ct, int ctlen, const uint8_t *pt, int ptlen)
{
    static uint8_t p[CMD_BUF_SIZE];
    p[0] = slot; p[1] = flags; w16(p + 2, tag); w16(p + 4, (uint16_t)ctlen); w16(p + 6, (uint16_t)ptlen);
    if (ctlen) memcpy(p + 8, ct, ctlen);
    if (ptlen) memcpy(p + 8 + ctlen, pt, ptlen);
    rpc(STEP, p, 8 + ctlen + ptlen);
    step_r *r = &last;
    r->err = rd32(4); r->state = rd8(8); r->alert_in = rd8(9); r->ct_len = rd16(10); r->pt_len = rd16(12);
    r->alert_out = rd8(14); r->fail_reason = rd8(15); r->verify_flags = (uint32_t)rd32(16);
    CHECK(reply_size == 20 + r->ct_len + r->pt_len, "step reply size %d != 20 + %d + %d", reply_size, r->ct_len, r->pt_len);
    CHECK(r->ct_len + r->pt_len <= 1024, "step output cap");
    CHECK(r->state <= FAILED, "state range");
    CHECK((r->state == FAILED) || r->fail_reason == 0, "fail_reason only with FAILED");
    if (reply_size >= 20) memcpy(r->data, B.data + 20, reply_size - 20);
    return r;
}

typedef struct { int err; uint16_t ct_len; uint8_t data[1100]; } close_r;
static close_r tls_close(uint8_t slot, uint16_t tag)
{
    uint8_t p[4] = { slot, 0 };
    w16(p + 2, tag);
    rpc(CLOSE, p, 4);
    close_r r = { rd32(4), 0, { 0 } };
    CHECK(reply_size >= 12, "close reply size %d", reply_size);
    if (reply_size >= 12) {
        r.ct_len = rd16(8);
        CHECK(reply_size == 12 + r.ct_len, "close reply size %d != 12 + %d", reply_size, r.ct_len);
        CHECK(rd16(10) == 0, "close reply reserved zeroed");
        memcpy(r.data, B.data + 12, r.ct_len < sizeof(r.data) ? r.ct_len : sizeof(r.data));
    }
    return r;
}

typedef struct {
    int err; uint32_t ct_in, ct_out, pt_in, pt_out; uint16_t version, suite, group; uint8_t state, sessions, time_source;
    uint8_t entropy, ems; uint16_t block_max_ms; uint8_t spki[32];
} stats_r;
static stats_r tls_stats(uint8_t slot, uint16_t tag)
{
    uint8_t p[4] = { slot, 0 };
    w16(p + 2, tag);
    rpc(STATS, p, 4);
    stats_r r;
    memset(&r, 0, sizeof(r));
    r.err = rd32(4);
    CHECK(reply_size == 96, "stats reply size %d", reply_size);
    r.ct_in = rd32(20); r.ct_out = rd32(24); r.pt_in = rd32(28); r.pt_out = rd32(32);
    r.version = rd16(40); r.suite = rd16(42); r.group = rd16(44); r.state = rd8(46); r.sessions = rd8(47);
    r.time_source = rd8(56); r.entropy = rd8(57); r.ems = rd8(58); r.block_max_ms = rd16(60);
    rd(64, r.spki, 32);
    CHECK(rd32(8) == 111111 && rd32(48) == 4321, "stats: heap and stack filled");
    CHECK(rd8(59) == 0 && rd16(62) == 0, "stats reserved zeroed");
    return r;
}

static int tls_close_all(void)
{
    rpc(CLOSE_ALL, NULL, 0);
    CHECK(reply_size == 8, "close_all reply size %d", reply_size);
    return rd32(4);
}

typedef struct { int err; uint8_t reject; } setca_r;
static setca_r tls_set_ca(const uint8_t *der, int len, uint16_t ca_tag)
{
    static uint8_t p[1600];
    w16(p, (uint16_t)len); w16(p + 2, ca_tag);
    memcpy(p + 4, der, len);
    rpc(SET_CA, p, 4 + len);
    setca_r r = { rd32(4), rd8(8) };
    CHECK(reply_size == 12, "set_ca reply size %d", reply_size);
    CHECK(rd8(9) == 0 && rd8(10) == 0 && rd8(11) == 0, "set_ca reserved zeroed");
    return r;
}

/* ---- files from mkpki.sh ---- */
static int load(const char *name, uint8_t *buf, int cap)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", getenv("PKI"), name);
    FILE *f = fopen(path, "rb");
    if (!f) { printf("  missing %s\n", path); exit(3); }
    int n = (int)fread(buf, 1, cap, f);
    fclose(f);
    return n;
}
static char *pki(const char *name)
{
    static char paths[8][512];
    static int k;
    char *p = paths[k++ % 8];
    snprintf(p, 512, "%s/%s", getenv("PKI"), name);
    return p;
}

/* ---- the server ---- */
static const char *cur_case;
static int case_index;
static pid_t srv_pid;
static char srv_log[512];

static int log_has(const char *needle)
{
    FILE *f = fopen(srv_log, "r");
    char line[1024];
    int n = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) n++;
    fclose(f);
    return n;
}
static int log_line(const char *prefix, char *out, int cap)
{
    FILE *f = fopen(srv_log, "r");
    char line[1024];
    int found = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, prefix, strlen(prefix))) {
            snprintf(out, cap, "%s", line + strlen(prefix));
            out[strcspn(out, "\n")] = 0;
            found = 1;
        }
    }
    fclose(f);
    return found;
}

// Starts m3srv with the given arguments (NULL-terminated) and connects to it
static int srv_start(const char *mode, ...)
{
    int port = atoi(getenv("PORTBASE") ? getenv("PORTBASE") : "23000") + case_index;
    char ports[16];
    snprintf(ports, sizeof(ports), "%d", port);
    const char *argv[24] = { getenv("M3SRV"), ports, mode };
    int argc = 3;
    va_list ap;
    va_start(ap, mode);
    static char named[22][600];
    for (const char *a; (a = va_arg(ap, const char *)) != NULL && argc < 22; argc++) {
        // PKI paths become crt= / key= arguments
        size_t n = strlen(a);
        if (n > 4 && (!strcmp(a + n - 4, ".pem") || !strcmp(a + n - 4, ".key"))) {
            snprintf(named[argc], sizeof(named[argc]), "%s=%s", strcmp(a + n - 4, ".pem") ? "key" : "crt", a);
            argv[argc] = named[argc];
        } else {
            argv[argc] = a;
        }
    }
    va_end(ap);
    argv[argc] = NULL;
    snprintf(srv_log, sizeof(srv_log), "%s/%s.srv.log", getenv("LOGDIR"), cur_case);
    unlink(srv_log);
    srv_pid = fork();
    if (srv_pid == 0) {
        int fd = open(srv_log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        dup2(fd, 1); dup2(fd, 2);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    for (int i = 0; i < 200 && !log_has("LISTEN"); i++) usleep(10000);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("connect"); exit(3); }
    return fd;
}
static void srv_end(int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        if (waitpid(srv_pid, NULL, WNOHANG) == srv_pid) { srv_pid = 0; return; }
        usleep(10000);
    }
    kill(srv_pid, SIGKILL);
    waitpid(srv_pid, NULL, 0);
    srv_pid = 0;
}

/* ---- the Ultimate's pump ---- */
typedef struct {
    int fd; uint8_t slot; uint16_t tag;
    uint8_t sock[1536]; int socklen; int eof;
    uint8_t pt[65536]; int ptlen;
    int state; step_r r;
} conn_t;

// Reads what the socket has, waiting up to ms for the first byte and quiet_ms for more, up to cap bytes
static int gather(conn_t *c, int ms, int quiet_ms, int cap)
{
    int got = 0;
    for (int wait = ms; c->socklen < cap; wait = quiet_ms) {
        struct pollfd pf = { c->fd, POLLIN, 0 };
        if (poll(&pf, 1, wait) <= 0) break;
        ssize_t n = recv(c->fd, c->sock + c->socklen, cap - c->socklen, 0);
        if (n <= 0) { c->eof = 1; break; }
        c->socklen += (int)n; got += (int)n;
    }
    return got;
}

// One step: the held ciphertext in, ct_out to the socket, plaintext collected (only from ESTABLISHED or CLOSED steps)
static step_r *pump_step(conn_t *c, uint8_t flags, const uint8_t *pt, int ptlen)
{
    step_r *r = tls_step(c->slot, c->tag, flags, c->sock, c->socklen, pt, ptlen);
    if (r->err == 0 || r->state == FAILED || r->state == CLOSED) c->socklen = 0;
    if (r->ct_len) send(c->fd, r->data, r->ct_len, 0);
    if (r->pt_len && (r->state == ESTABLISHED || r->state == CLOSED) && c->ptlen + r->pt_len <= (int)sizeof(c->pt)) {
        memcpy(c->pt + c->ptlen, r->data + r->ct_len, r->pt_len);
        c->ptlen += r->pt_len;
    }
    c->state = r->state;
    c->r = *r;
    return r;
}

static int handshake(conn_t *c)
{
    for (int i = 0; i < 400; i++) {
        if (c->socklen == 0) gather(c, 20, 5, sizeof(c->sock));
        pump_step(c, 0, NULL, 0);
        if (c->state != HANDSHAKING) break;
    }
    return c->state;
}

// Opens (slot 0, tag 1 unless set) and handshakes against a started server
static int connect_open(conn_t *c, int fd, uint8_t trust, uint8_t opts, uint16_t ca_tag, const uint8_t *pin, const char *sni)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd; c->slot = 0; c->tag = 1;
    open_r o = tls_open(c->slot, c->tag, trust, opts, ca_tag, pin, sni);
    CHECK(o.err == 0, "open: err 0x%x reason %d", o.err, o.reason);
    if (o.err) return -1;
    CHECK(o.slot == c->slot, "open reply names the slot");
    return handshake(c);
}

// Reads with plain steps until n plaintext bytes arrived or nothing comes for a while
static void read_pt(conn_t *c, int n)
{
    for (int idle = 0; c->ptlen < n && idle < 20 && c->state == ESTABLISHED; ) {
        if (c->socklen == 0) gather(c, 20, 5, sizeof(c->sock));
        int before = c->ptlen;
        step_r *r = pump_step(c, 0, NULL, 0);
        idle = (c->ptlen > before || r->ct_len) ? 0 : idle + 1;
    }
}
static int pattern_ok(const uint8_t *p, int n, long off, int seed)
{
    for (int i = 0; i < n; i++) if (p[i] != pattern(off + i, seed)) return 0;
    return 1;
}
static void client_pattern(uint8_t *p, int n, long off) { for (int i = 0; i < n; i++) p[i] = pattern(off + i, SEED_CLIENT); }

/* ================= cases ================= */

/* 5.1: the TLS task, its queue, the dispatcher's stack */
static void c_task(void)
{
    fake_task_t *tls = find_task("TLS"), *disp = find_task("Dispatch Task");
    CHECK(tls != NULL, "a task named TLS exists");
    if (tls) {
        CHECK(tls->core == 1, "TLS task pinned to core 1 (core %d)", tls->core);
        CHECK(tls->stack == 8192, "TLS_TASK_STACK 8192 (%u)", tls->stack);
        CHECK(disp && tls->prio == disp->prio && tls->prio == tskIDLE_PRIORITY + 1, "TLS task priority equals the dispatcher's");
    }
    CHECK(disp && disp->stack == 3072, "dispatcher stack back to 3072 (%u)", disp ? disp->stack : 0);
    int q2 = 0;
    for (int i = 0; i < nqueues; i++) if (queues[i].cap == 2 && queues[i].size == (int)sizeof(command_buf_t *)) q2++;
    CHECK(q2 == 1, "one tls_queue of depth 2 holding buffer pointers");
}

/* 5.1: a full queue answers at once with ESP_ERR_TIMEOUT, in the command's own reply shape; GET_RANDOM still runs */
static void c_queue_full(void)
{
#ifdef BASE_ENGINE
    CHECK(0, "the M2 dispatcher has no TLS queue");
#else
    static command_buf_t held[2];
    for (int i = 0; i < 2; i++) {
        memset(&held[i], 0, sizeof(held[i]));
        held[i].data[0] = STATS; held[i].size = 12;
        int before = transmitted;
        dispatch_command(&held[i]);
        CHECK(transmitted == before, "queued, not answered");
    }
    static const struct { uint8_t cmd; int size; } shapes[] = {
        { OPEN, 12 }, { STEP, 20 }, { CLOSE, 12 }, { STATS, 96 }, { CLOSE_ALL, 8 }, { SET_CA, 12 } };
    for (int i = 0; i < 6; i++) {
        uint8_t p[64] = { 0 };
        put_request(shapes[i].cmd, p, (shapes[i].cmd == OPEN) ? 48 : 8);
        int before = transmitted;
        dispatch_command(&B);
        CHECK(transmitted == before + 1, "cmd %02x answered at once when the queue is full", shapes[i].cmd);
        CHECK(B.data[0] == shapes[i].cmd && rd16(2) == seq, "header echoed");
        CHECK(rd32(4) == E_TIMEOUT, "cmd %02x: esp_err ESP_ERR_TIMEOUT (got 0x%x)", shapes[i].cmd, rd32(4));
        CHECK(B.size == shapes[i].size, "cmd %02x: reply size %d, want %d", shapes[i].cmd, B.size, shapes[i].size);
        if (shapes[i].cmd == STEP) CHECK(rd8(9) == 0xFF && rd8(14) == 0xFF, "no alerts in a busy STEP reply");
        if (shapes[i].cmd == OPEN) CHECK(rd8(8) == 0xFF, "no slot in a busy OPEN reply");
    }
    uint8_t len[2] = { 16, 0 };
    put_request(0x13, len, 2); // GET_RANDOM
    int before = transmitted;
    dispatch_command(&B);
    CHECK(transmitted == before + 1 && rd32(4) == 0 && B.size == 12 + 16, "GET_RANDOM served by the dispatcher while TLS is busy");
#endif
}

/* 5.2 STATS block_max_ms: the longest dispatcher iteration since boot */
static void c_block_max(void)
{
    stats_r s = tls_stats(0xFF, 0);
    CHECK(s.err == 0, "global STATS (slot 0xFF, tag 0) err 0x%x", s.err);
    CHECK(s.block_max_ms < 1000, "block_max_ms small before (%u)", s.block_max_ms);
    uint8_t baud[8] = { 0 };
    rpc(0x03, baud, 8); // SET_BAUD blocks the dispatcher for a second (vTaskDelay)
    s = tls_stats(0xFF, 0);
    CHECK(s.block_max_ms >= 1000 && s.block_max_ms < 1500, "block_max_ms covers the 1 s SET_BAUD (%u)", s.block_max_ms);
    CHECK(s.entropy == ENTROPY_RADIO, "entropy_source at 57 (%u)", s.entropy);
}

/* Layouts: sizes that do not match are refused, nothing is read past the request */
static void c_sizes(void)
{
    uint8_t p[64] = { 0 };
    p[1] = 3; p[2] = 0; w16(p + 8, 1);                         // sni_len 3, but no sni bytes
    rpc(OPEN, p, 48);
    CHECK(rd32(4) == E_INVALID_ARG && reply_size == 12, "OPEN size != 52 + sni_len -> INVALID_ARG");
    rpc(OPEN, p, 47);
    CHECK(rd32(4) == E_INVALID_ARG, "short OPEN -> INVALID_ARG");
    uint8_t s[16] = { 0, 0, 1, 0, 4, 0, 0, 0 };                // ct_in_len 4, nothing follows
    rpc(STEP, s, 8);
    CHECK(rd32(4) == E_INVALID_ARG && reply_size == 20, "STEP size != 12 + lengths -> INVALID_ARG");
    rpc(CLOSE, s, 3);
    CHECK(rd32(4) == E_INVALID_ARG && reply_size == 12, "short CLOSE -> INVALID_ARG");
    uint8_t der[2048];
    int n = load("ca.der", der, sizeof(der));
    CHECK(tls_set_ca(der, n, 5).err == 0, "a CA held under tag 5");
    uint8_t c[8] = { 10, 0, 5, 0 };                            // der_len 10, no der
    rpc(SET_CA, c, 4);
    CHECK(rd32(4) == E_INVALID_ARG && rd8(8) == 0, "SET_CA size != 8 + der_len -> INVALID_ARG");
    CHECK(tls_open(0, 1, CUSTOM, 0, 5, NULL, "m3.test").reason == 3, "a malformed SET_CA leaves no CA held");
}

/* OPEN argument checks (nothing opened, no state touched) */
static void c_open_args(void)
{
    uint8_t pin[32] = { 1 };
    CHECK(tls_open(0, 1, 3, 0, 0, NULL, "m3.test").err == E_INVALID_ARG, "trust 3 refused");
    CHECK(tls_open(0, 1, BUNDLE, 0x02, 0, NULL, "m3.test").err == E_INVALID_ARG, "opts bit1 refused");
    CHECK(tls_open(0, 1, BUNDLE, 0x80, 0, NULL, "m3.test").err == E_INVALID_ARG, "opts bit7 refused");
    CHECK(tls_open(2, 1, PIN, 0, 0, pin, "m3.test").err == E_INVALID_ARG, "slot 2 refused");
    CHECK(tls_open(0xFF, 1, PIN, 0, 0, pin, "m3.test").err == E_INVALID_ARG, "slot 0xFF refused");
    CHECK(tls_open(0, 0, PIN, 0, 0, pin, "m3.test").err == E_INVALID_ARG, "tag 0 refused");
    CHECK(tls_open(0, 1, BUNDLE, 0, 0, NULL, "").err == E_INVALID_ARG, "BUNDLE without a name refused");
    CHECK(tls_open(0, 1, CUSTOM, 0, 7, NULL, "").err == E_INVALID_ARG, "CUSTOM without a name refused");
    CHECK(tls_open2(0, 1, PIN, 0, 0, pin, "m3\0test", 7).err == E_INVALID_ARG, "a NUL in the name refused");
    g_time_source = 2;
    CHECK(tls_open(0, 1, PIN, 0, 0, pin, "m3.test").err == E_INVALID_ARG, "time_source 2 refused");
    g_time_source = 1;
    stats_r s = tls_stats(0xFF, 0);
    CHECK(s.sessions == 0, "no session opened by a refused OPEN");
}

/* 5.1 the entropy gate: reason 1 and no random byte drawn */
static void c_no_entropy(void)
{
    entropy = ENTROPY_NONE;
    uint8_t pin[32] = { 1 };
    long draws = rng_draws;
    open_r o = tls_open(0, 1, PIN, 0, 0, pin, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 1, "no entropy -> INVALID_STATE reason 1 (0x%x, %d)", o.err, o.reason);
    CHECK(o.slot == 0xFF, "no slot on failure");
    CHECK(rng_draws == draws, "no random bytes drawn before the gate");
}

/* 3.5 time: BUNDLE/CUSTOM need a trusted clock (reason 2); PIN does not; time_source 0 is never a clock */
static void c_no_time(void)
{
    uint8_t pin[32] = { 1 };
    fake_now = 1000;                          // a 1970 clock
    g_time_source = 1; g_unix_time = 0;
    open_r o = tls_open(0, 1, BUNDLE, 0, 0, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 2, "BUNDLE without time -> reason 2 (0x%x, %d)", o.err, o.reason);
    g_time_source = 0; g_unix_time = (uint32_t)real_now();
    o = tls_open(0, 1, BUNDLE, 0, 0, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 2, "unix_time with time_source 0 is not taken (0x%x, %d)", o.err, o.reason);
    CHECK(fake_now == 1000, "clock untouched by time_source 0");
    o = tls_open(0, 1, PIN, 0, 0, pin, "m3.test");
    CHECK(o.err == 0, "PIN needs no clock (0x%x, %d)", o.err, o.reason);
    g_time_source = 1;
    o = tls_open(0, 2, BUNDLE, 0, 0, NULL, "m3.test");
    CHECK(o.err == 0 && fake_now == (time_t)g_unix_time, "time_source 1 sets the clock (0x%x)", o.err);
    stats_r s = tls_stats(0, 2);
    CHECK(s.time_source == 1, "session time_source NIOS (%u)", s.time_source);
}

/* 3.2 PIN accept, SPKI in STATS, the ClientHello carries SNI */
static void pin_case(const char *crt, const char *key, const char *spkif, const char *ver, uint16_t want_version)
{
    uint8_t spki[32];
    load(spkif, spki, 32);
    int fd = srv_start("tls", ver, pki(crt), pki(key), "run=echo", NULL);
    conn_t c;
    fake_now = 1000; g_time_source = 0; g_unix_time = 0;      // PIN works without any clock
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == ESTABLISHED, "PIN with the right key -> ESTABLISHED (state %d reason %d err -0x%x)", st, c.r.fail_reason, -c.r.err);
    stats_r s = tls_stats(0, 1);
    CHECK(s.version == want_version, "version 0x%04x", s.version);
    CHECK(!memcmp(s.spki, spki, 32), "STATS spki_sha256 is the leaf's SPKI hash");
    uint8_t msg[300];
    client_pattern(msg, sizeof(msg), 0);
    step_r *r = pump_step(&c, NO_READ, msg, sizeof(msg));
    CHECK(r->err == 0 && r->pt_len == 0, "write step");
    read_pt(&c, 300);
    CHECK(c.ptlen == 300 && pattern_ok(c.pt, 300, 0, SEED_CLIENT), "echo of 300 B (%d)", c.ptlen);
    close(fd);
    srv_end(2000);
}
static void c_pin_accept13(void) { pin_case("leaf.chain.pem", "leaf.key", "leaf.spki", "ver=13", 0x0304); }
static void c_pin_accept12(void) { pin_case("leafrsa.chain.pem", "leafrsa.key", "leafrsa.spki", "ver=12", 0x0303); }

/* 3.2 PIN checks the key only (U3): a name the certificate does not carry still opens */
static void c_pin_name_ignored(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "not-the-name.test");
    CHECK(st == ESTABLISHED, "PIN with a matching key and a wrong name -> ESTABLISHED (%d, reason %d, w 0x%x)", st,
          c.r.fail_reason, c.r.verify_flags);
    close(fd);
    srv_end(2000);
}

/* Section 2, the U3 exception: in PIN mode mbedTLS still checks extendedKeyUsage, a secondary check -> reason 4 */
static void c_pin_eku(void)
{
    uint8_t spki[32];
    load("leafcli.spki", spki, 32);
    int fd = srv_start("tls", "ver=13", "ownusage=0", pki("leafcli.chain.pem"), pki("leafcli.key"), NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == FAILED && c.r.fail_reason == R_CERT, "matching key, clientAuth-only EKU -> reason 4, not 5 (%d, %d)", st,
          c.r.fail_reason);
    CHECK(c.r.err == -0x7A00, "esp_err BAD_CERTIFICATE (-0x%x)", -c.r.err);
    CHECK(c.r.verify_flags == 0x1000, "verify_flags BADCERT_EXT_KEY_USAGE only (0x%08x)", c.r.verify_flags);
    close(fd);
    srv_end(2000);
}

/* 3.5: the clock from OPEN is the one certificates are checked against: a far-future unix_time expires the leaf */
static void c_custom_expired(void)
{
    uint8_t der[2048];
    int n = load("ca.der", der, sizeof(der));
    CHECK(tls_set_ca(der, n, 5).err == 0, "SET_CA");
    g_unix_time = (uint32_t)(real_now() + 20LL * 365 * 86400);
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), NULL);
    conn_t c;
    int st = connect_open(&c, fd, CUSTOM, 0, 5, NULL, "m3.test");
    CHECK(st == FAILED && c.r.fail_reason == R_CERT, "leaf expired by the clock OPEN set -> reason 4 (%d, %d)", st, c.r.fail_reason);
    CHECK((c.r.verify_flags & 0x01) && (c.r.verify_flags & 0x08) == 0, "verify_flags EXPIRED, trusted (0x%08x)", c.r.verify_flags);
    close(fd);
    srv_end(2000);
}

/* 3.2 / 5.2 pin mismatch -> reason 5, including a one-bit-off pin and an all-zero pin (never gated on non-zero) */
static void c_pin_mismatch(void)
{
    uint8_t good[32], bits[32], zero[32] = { 0 };
    load("leaf.spki", good, 32);
    memcpy(bits, good, 32);
    bits[17] ^= 0x04;
    const uint8_t *pins[3] = { bits, zero, NULL };
    const char *names[3] = { "one bit off", "all zero", "another key" };
    uint8_t other[32];
    load("leafrsa.spki", other, 32);
    pins[2] = other;
    for (int i = 0; i < 3; i++) {
        case_index += 100;
        int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), NULL);
        conn_t c;
        int st = connect_open(&c, fd, PIN, 0, 0, pins[i], "m3.test");
        CHECK(st == FAILED && c.r.fail_reason == R_PIN, "%s: FAILED reason 5 (state %d reason %d)", names[i], st, c.r.fail_reason);
        CHECK(c.r.verify_flags == 0x08, "%s: verify_flags 0x%08x", names[i], c.r.verify_flags);
        CHECK(c.r.err == -0x2700, "%s: esp_err -0x%04x", names[i], -c.r.err);
        close(fd);
        srv_end(2000);
    }
}

/* 1.1 PIN name handling: SNI with a name; no SNI with NONE (set_hostname(NULL)) */
static void c_pin_sni(void)
{
    uint8_t pin[32] = { 9 };
    int fd = srv_start("raw:ch", NULL);
    conn_t c;
    memset(&c, 0, sizeof(c)); c.fd = fd; c.slot = 1; c.tag = 3;
    CHECK(tls_open2(1, 3, PIN, 0, 0, pin, "", 0).err == 0, "PIN with no name opens");
    pump_step(&c, 0, NULL, 0);
    close(fd);
    srv_end(2000);
    CHECK(log_has("CH ext") == 1 && log_has("CH sni") == 0, "no SNI without a name");
    case_index += 100;
    fd = srv_start("raw:ch", NULL);
    c.fd = fd;
    CHECK(tls_open(1, 4, PIN, 0, 0, pin, "pin.m3.test").err == 0, "PIN with a name opens");
    c.tag = 4;
    pump_step(&c, 0, NULL, 0);
    close(fd);
    srv_end(2000);
    CHECK(log_has("CH sni pin.m3.test") == 1, "SNI sent with a name");
}

/* 3.3 CUSTOM: the uploaded CA is the only anchor, matched by ca_tag */
static void c_custom_accept(void)
{
    uint8_t der[2048];
    int n = load("ca.der", der, sizeof(der));
    setca_r r = tls_set_ca(der, n, 5);
    CHECK(r.err == 0 && r.reject == 0, "SET_CA loads (0x%x, %d)", r.err, r.reject);
    int fd = srv_start("tls", "ver=1213", pki("leaf.chain.pem"), pki("leaf.key"), "run=echo", NULL);
    conn_t c;
    int st = connect_open(&c, fd, CUSTOM, 0, 5, NULL, "m3.test");
    CHECK(st == ESTABLISHED, "CUSTOM under the uploaded CA -> ESTABLISHED (%d, reason %d, -0x%x, w 0x%x)", st, c.r.fail_reason,
          -c.r.err, c.r.verify_flags);
    close(fd);
    srv_end(2000);
}

/* 5.2 the module's ca_tag check: reason 3 NO_CUSTOM_CA */
static void c_custom_catag(void)
{
    uint8_t der[2048];
    int n = load("ca.der", der, sizeof(der));
    open_r o = tls_open(0, 1, CUSTOM, 0, 5, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 3, "no CA held -> reason 3 (0x%x, %d)", o.err, o.reason);
    CHECK(tls_set_ca(der, n, 5).err == 0, "SET_CA tag 5");
    o = tls_open(0, 1, CUSTOM, 0, 6, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 3, "ca_tag 6 != held 5 -> reason 3 (0x%x, %d)", o.err, o.reason);
    o = tls_open(0, 1, CUSTOM, 0, 0, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 3, "ca_tag 0 never matches (0x%x, %d)", o.err, o.reason);
    o = tls_open(0, 1, CUSTOM, 0, 5, NULL, "m3.test");
    CHECK(o.err == 0, "ca_tag 5 == held 5 opens (0x%x, %d)", o.err, o.reason);
    CHECK(tls_close_all() == 0, "CLOSE_ALL");
    o = tls_open(0, 2, CUSTOM, 0, 5, NULL, "m3.test");
    CHECK(o.err == E_INVALID_STATE && o.reason == 3, "CLOSE_ALL clears the CA -> reason 3 (0x%x, %d)", o.err, o.reason);
    CHECK(tls_set_ca(der, n, 0).err == E_INVALID_ARG, "SET_CA with ca_tag 0 refused");
}

/* CUSTOM verifies against the uploaded CA only (never the bundle), with CA mode's flags */
static void c_custom_untrusted(void)
{
    uint8_t der[2048];
    int n = load("other.der", der, sizeof(der));
    CHECK(tls_set_ca(der, n, 9).err == 0, "SET_CA other root");
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), NULL); // leaf is under ca, which the bundle holds
    conn_t c;
    int st = connect_open(&c, fd, CUSTOM, 0, 9, NULL, "m3.test");
    CHECK(st == FAILED && c.r.fail_reason == R_CERT, "a leaf the uploaded CA did not sign fails, reason 4 (%d, %d)", st, c.r.fail_reason);
    CHECK(c.r.verify_flags == 0x08, "verify_flags NOT_TRUSTED exactly (0x%08x)", c.r.verify_flags);
    close(fd);
    srv_end(2000);
}

/* 5.2: a CA replaced while a CUSTOM session handshakes is not freed under it */
static void c_custom_ca_replaced(void)
{
    uint8_t der[2048], der2[2048];
    int n = load("ca.der", der, sizeof(der)), n2 = load("other.der", der2, sizeof(der2));
    CHECK(tls_set_ca(der, n, 5).err == 0, "SET_CA");
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), NULL);
    conn_t c;
    memset(&c, 0, sizeof(c)); c.fd = fd; c.tag = 1;
    CHECK(tls_open(0, 1, CUSTOM, 0, 5, NULL, "m3.test").err == 0, "open");
    pump_step(&c, 0, NULL, 0);                    // ClientHello out
    CHECK(tls_set_ca(der2, n2, 6).err == 0, "SET_CA replaces the CA mid-handshake");
    CHECK(handshake(&c) == ESTABLISHED, "the session verifies with the CA it opened with (state %d, reason %d)", c.state,
          c.r.fail_reason);
    close(fd);
    srv_end(2000);
}

/* 3.3 upload-time refusals, their precedence, and "on any error the module holds NO CA" */
static void c_set_ca_rejects(void)
{
    static const struct { const char *f; int err; int reject; } t[] = {
        { "rsa1024.der", E_INVALID_ARG, 1 }, { "rsa1024nca.der", E_INVALID_ARG, 1 },
        { "k1.der", E_INVALID_ARG, 3 }, { "k1nca.der", E_INVALID_ARG, 3 },
        { "notca.der", E_INVALID_ARG, 4 }, { "nobc.der", E_INVALID_ARG, 4 }, { "kunosign.der", E_INVALID_ARG, 4 },
        { "kuenc.der", E_INVALID_ARG, 4 },
        { "noku.der", 0, 0 }, { "v1.der", 0, 0 }, { "rsa2048ca.der", 0, 0 }, { "ca.der", 0, 0 },
    };
    uint8_t der[2048], good[2048];
    int gn = load("ca.der", good, sizeof(good));
    for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        CHECK(tls_set_ca(good, gn, 40).err == 0, "a good CA first");
        int n = load(t[i].f, der, sizeof(der));
        setca_r r = tls_set_ca(der, n, (uint16_t)(50 + i));
        CHECK(r.err == t[i].err && r.reject == t[i].reject, "%s: err 0x%x reject %d, want 0x%x %d", t[i].f, r.err, r.reject,
              t[i].err, t[i].reject);
        open_r o = tls_open(0, 1, CUSTOM, 0, 40, NULL, "m3.test");
        CHECK(o.reason == 3, "%s: the earlier CA is gone (reason %d)", t[i].f, o.reason);
        o = tls_open(0, 1, CUSTOM, 0, (uint16_t)(50 + i), NULL, "m3.test");
        CHECK((o.err == 0) == (t[i].err == 0), "%s: held exactly when loaded (0x%x %d)", t[i].f, o.err, o.reason);
    }
    int n = load("garbage.der", der, sizeof(der));
    setca_r r = tls_set_ca(der, n, 90);
    CHECK(r.err < -1 && r.reject == 0, "garbage: a negative parse code <= -2, reject 0 (%d, %d)", r.err, r.reject);
    CHECK(tls_open(0, 1, CUSTOM, 0, 90, NULL, "m3.test").reason == 3, "garbage: no CA held");
    CHECK(tls_set_ca(der, 0, 91).err == E_INVALID_ARG, "der_len 0 refused");
}

/* 3.4 BUNDLE through the verify wrapper: accept; unknown root is EXACTLY 0x00000008; a wrong name has CN_MISMATCH */
static void bundle_case(const char *crt, const char *key, int want_state, uint32_t want_flags, uint32_t mask)
{
    int fd = srv_start("tls", "ver=1213", pki(crt), pki(key), NULL);
    conn_t c;
    int st = connect_open(&c, fd, BUNDLE, 0, 0, NULL, "m3.test");
    CHECK(st == want_state, "%s: state %d, want %d (reason %d, -0x%x, w 0x%08x)", crt, st, want_state, c.r.fail_reason, -c.r.err,
          c.r.verify_flags);
    if (want_state == FAILED) {
        CHECK(c.r.fail_reason == R_CERT, "%s: reason 4 (%d)", crt, c.r.fail_reason);
        CHECK((c.r.verify_flags & mask) == want_flags, "%s: verify_flags 0x%08x", crt, c.r.verify_flags);
    }
    close(fd);
    srv_end(2000);
}
static void c_bundle_accept(void) { bundle_case("leaf.chain.pem", "leaf.key", ESTABLISHED, 0, 0); }
static void c_bundle_unknown_root(void) { bundle_case("leafother.chain.pem", "leafother.key", FAILED, 0x08, 0xFFFFFFFF); }
static void c_bundle_name(void) { bundle_case("leafname.chain.pem", "leafname.key", FAILED, 0x04, 0x04); }

/* 1.7 / 5.2 versions, suites, groups (the negotiated group, never 0), EMS */
static void hs_case(const char *ver, const char *groups, uint16_t want_version, uint16_t want_group, int want_ems,
                    const char *crt, const char *key)
{
    uint8_t spki[32];
    load(!strcmp(crt, "leaf.chain.pem") ? "leaf.spki" : "leafrsa.spki", spki, 32);
    int fd = srv_start("tls", ver, groups, pki(crt), pki(key), NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == ESTABLISHED, "%s %s: ESTABLISHED (%d, reason %d, -0x%x)", ver, groups, st, c.r.fail_reason, -c.r.err);
    stats_r s = tls_stats(0, 1);
    CHECK(s.version == want_version, "version 0x%04x", s.version);
    CHECK(s.group == want_group, "%s %s: group 0x%04x, want 0x%04x (the server's only group)", ver, groups, s.group, want_group);
    CHECK(s.ems == want_ems, "ems %d, want %d", s.ems, want_ems);
    char line[256];
    for (int i = 0; i < 200 && !log_has("HS ok "); i++) usleep(10000); // the server takes our Finished after the step
    CHECK(log_line("HS ok ", line, sizeof(line)), "server finished the handshake");
    char want[64];
    snprintf(want, sizeof(want), "version %04x suite %04x", want_version, s.suite);
    CHECK(strstr(line, want) != NULL, "server agrees on version and suite: '%s' vs '%s'", line, want);
    static const uint16_t six[] = { 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA9, 0xCCA8 };
    int ok = (want_version == 0x0304) ? (s.suite >= 0x1301 && s.suite <= 0x1303) : 0;
    for (int i = 0; i < 6 && want_version == 0x0303; i++) ok |= s.suite == six[i];
    CHECK(ok, "suite 0x%04x is allowed", s.suite);
    close(fd);
    srv_end(2000);
}
static void c_hs13_x25519(void) { hs_case("ver=13", "groups=001d", 0x0304, 0x001D, 0, "leaf.chain.pem", "leaf.key"); }
static void c_hs13_hrr_p256(void) { hs_case("ver=13", "groups=0017", 0x0304, 0x0017, 0, "leaf.chain.pem", "leaf.key"); }
static void c_hs13_hrr_p384(void) { hs_case("ver=13", "groups=0018", 0x0304, 0x0018, 0, "leaf.chain.pem", "leaf.key"); }
static void c_hs12_p256(void) { hs_case("ver=12", "groups=0017", 0x0303, 0x0017, 1, "leaf.chain.pem", "leaf.key"); }
static void c_hs12_x25519(void) { hs_case("ver=12", "groups=001d", 0x0303, 0x001D, 1, "leafrsa.chain.pem", "leafrsa.key"); }
static void c_hs12_p521(void) { hs_case("ver=12", "groups=0019", 0x0303, 0x0019, 1, "leafrsa.chain.pem", "leafrsa.key"); }

/* 1.7 the ClientHello: versions, suites exactly, groups exactly, SHA-256+ signatures, EMS, no 1.2 ticket extension */
static void c_client_hello(void)
{
    uint8_t pin[32] = { 3 };
    for (int require = 0; require < 2; require++) {
        case_index += 100;
        int fd = srv_start("raw:ch", NULL);
        conn_t c;
        memset(&c, 0, sizeof(c)); c.fd = fd; c.tag = 1;
        CHECK(tls_open(0, 1, PIN, require ? REQUIRE_TLS13 : 0, 0, pin, "m3.test").err == 0, "open");
        pump_step(&c, 0, NULL, 0);
        close(fd);
        srv_end(2000);
        char v[256], s[512], g[256], a[512], e[256];
        CHECK(log_line("CH versions ", v, sizeof(v)), "supported_versions present");
        CHECK(!strcmp(v, require ? "0304" : "0304,0303"), "versions '%s'", v);
        CHECK(log_line("CH suites ", s, sizeof(s)), "suites logged");
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (00ff) is the only extra allowed
        // REQUIRE_TLS13 offers no TLS 1.2 suite at all (mbedTLS filters them by the minimum version)
        const char *want = require ? "1303,1302,1301" : "1303,1302,1301,cca8,cca9,c02c,c030,c02b,c02f";
        char stripped[512];
        snprintf(stripped, sizeof(stripped), "%s", s);
        char *sc = strstr(stripped, ",00ff");
        if (sc) memmove(sc, sc + 5, strlen(sc + 5) + 1);
        CHECK(!strcmp(stripped, want), "suites exactly '%s' (got '%s')", want, s);
        CHECK(log_line("CH groups ", g, sizeof(g)) && !strcmp(g, "001d,0017,0018,0019"), "groups exactly 001d,0017,0018,0019 ('%s')", g);
        CHECK(log_line("CH sigalgs ", a, sizeof(a)), "signature_algorithms present");
        CHECK(!strstr(a, "0201") && !strstr(a, "0203") && !strstr(a, "0202") && !strstr(a, "0101") && !strstr(a, "0103"),
              "no SHA-1 or MD5 signature algorithm ('%s')", a);
        if (!require) CHECK(log_has("CH ems len 0") == 1, "extended_master_secret offered");
        CHECK(log_has("CH session_ticket") == 0, "no session_ticket extension");
        CHECK(log_line("CH ext ", e, sizeof(e)), "extensions logged");
        char rinfo[64];
        if (log_line("CH renegotiation_info len ", rinfo, sizeof(rinfo))) CHECK(atoi(rinfo) == 1, "renegotiation_info empty");
    }
}

/* 1.7 version refusals and the downgrade sentinel (fail_reason 1 and 2), and their neighbours */
static void raw_case(const char *what, uint8_t opts, int want_reason, uint32_t want_flags, int want_err, int want_alert_in)
{
    uint8_t pin[32] = { 3 };
    int fd = srv_start(what, NULL);
    conn_t c;
    memset(&c, 0, sizeof(c)); c.fd = fd; c.tag = 1;
    CHECK(tls_open(0, 1, PIN, opts, 0, pin, "m3.test").err == 0, "open");
    int st = handshake(&c);
    CHECK(st == FAILED, "%s opts %d: FAILED (%d)", what, opts, st);
    CHECK(c.r.fail_reason == want_reason, "%s opts %d: fail_reason %d, want %d (err -0x%x)", what, opts, c.r.fail_reason,
          want_reason, -c.r.err);
    if (want_reason == R_VERSION) CHECK((c.r.verify_flags & 0xFFFF) == want_flags, "version 0x%04x", c.r.verify_flags & 0xFFFF);
    if (want_err) CHECK(c.r.err == want_err, "esp_err -0x%04x, want -0x%04x", -c.r.err, -want_err);
    CHECK(c.r.alert_in == want_alert_in, "alert_in %d, want %d", c.r.alert_in, want_alert_in);
    close(fd);
    srv_end(2000);
}
static void c_require13_vs_12(void) { raw_case("raw:sh12", REQUIRE_TLS13, R_VERSION, 0x0303, -0x6600, 0xFF); }
static void c_sentinel(void) { raw_case("raw:sh12s", 0, R_DOWNGRADE, 0, -0x6600, 0xFF); }
static void c_sentinel_require13(void) { raw_case("raw:sh12s", REQUIRE_TLS13, R_VERSION, 0x0303, 0, 0xFF); }
static void c_version_below_12(void) { raw_case("raw:sh11", 0, R_VERSION, 0x0302, -0x6E80, 0xFF); }
static void c_sh12_bad_suite(void) { raw_case("raw:sh12suite", 0, R_NONE, 0, -0x6600, 0xFF); }
static void c_alert70(void) { raw_case("raw:alert70", 0, R_NONE, 0, -0x7780, 70); }
static void c_peer_closed(void) { raw_case("raw:cn", 0, R_PEER_CLOSED, 0, -0x7880, 0xFF); }

/* 1.7 EMS required: handshake_failure (40) and nothing after the ServerHello */
static void c_no_ems(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=12", "ems=0", pki("leaf.chain.pem"), pki("leaf.key"), NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == FAILED && c.r.fail_reason == R_NO_EMS, "no EMS -> FAILED reason 3 (%d, %d, -0x%x)", st, c.r.fail_reason, -c.r.err);
    static const uint8_t alert40[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
    CHECK(c.r.ct_len == 7 && !memcmp(c.r.data, alert40, 7), "the failing step sends exactly a plaintext fatal alert 40 (%d B)",
          c.r.ct_len);
    CHECK(c.r.alert_out == 40, "alert_out 40 (%d)", c.r.alert_out);
    close(fd);
    srv_end(2000);
    CHECK(log_has("HS alert 40") == 1, "the server received alert 40");
}

/* 5.2: the step that reaches ESTABLISHED returns no plaintext, even with application data behind the Finished */
static void c_established_no_pt(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=12", pki("leaf.chain.pem"), pki("leaf.key"), "run=app:100,drain", NULL);
    conn_t c;
    memset(&c, 0, sizeof(c)); c.fd = fd; c.tag = 1;
    CHECK(tls_open(0, 1, PIN, 0, 0, spki, "m3.test").err == 0, "open");
    int saw = 0;
    for (int i = 0; i < 200 && c.state == HANDSHAKING; i++) {
        if (c.socklen == 0) gather(&c, 50, 100, sizeof(c.sock)); // server Finished and the app record in one ct_in
        step_r *r = pump_step(&c, 0, NULL, 0);
        if (r->state == ESTABLISHED) { saw = 1; CHECK(r->pt_len == 0, "establishing step pt_out_len 0 (%d)", r->pt_len); }
    }
    CHECK(saw, "reached ESTABLISHED");
    read_pt(&c, 100);
    CHECK(c.ptlen == 100 && pattern_ok(c.pt, 100, 0, SEED_SERVER), "the 100 B come on the next steps (%d)", c.ptlen);
    close(fd);
    srv_end(2000);
}

/* E1 NO_READ (5.2): (a) with pt_in, (b) input-less, (c) then plain steps return exactly the pending plaintext */
static void c_e1_no_read(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), "run=app:3000,rd:10,drain", NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == ESTABLISHED, "established");
    // Feed the 3000-B record with plain steps until the first plaintext comes out
    for (int i = 0; i < 100 && c.ptlen == 0; i++) {
        if (c.socklen == 0) gather(&c, 50, 20, sizeof(c.sock));
        pump_step(&c, 0, NULL, 0);
    }
    CHECK(c.ptlen > 0 && c.ptlen < 3000, "part of the record came out (%d), the rest is held in the engine", c.ptlen);
    int first = c.ptlen;
    uint8_t w[10];
    client_pattern(w, 10, 0);
    step_r *r = pump_step(&c, NO_READ, w, 10);
    CHECK(r->err == 0 && r->pt_len == 0 && r->ct_len > 0, "(a) NO_READ with pt_in: ciphertext only (pt %d ct %d)", r->pt_len, r->ct_len);
    r = pump_step(&c, NO_READ, NULL, 0);
    CHECK(r->err == 0 && r->pt_len == 0, "(b) NO_READ, pt_in_len 0: pt_out_len 0 (%d)", r->pt_len);
    int steps = 0;
    while (c.ptlen < 3000 && steps < 10) {
        r = pump_step(&c, 0, NULL, 0);
        CHECK(r->pt_len <= 960, "(c) at most 960 B per step (%d)", r->pt_len);
        steps++;
        if (r->pt_len == 0) break;
    }
    CHECK(c.ptlen == 3000 && pattern_ok(c.pt, 3000, 0, SEED_SERVER), "(c) exactly the 3000 B in order (%d after %d first)", c.ptlen,
          first);
    close(fd);
    srv_end(2000);
    CHECK(log_has("RX total 10 bad 0") >= 1, "the server got the 10 B written with NO_READ");
}

/* E2 the warning-alert MUST-FIX: no_renegotiation warnings then data in ONE ct_in, and the queued variant */
static void e2_case(const char *ver, int queued)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    const char *run = queued ? "run=sleep:300,app:1200,wa:100,wa:100,app:100,drain" : "run=sleep:300,wa:100,wa:100,app:100,drain";
    int fd = srv_start("tls", ver, pki("leaf.chain.pem"), pki("leaf.key"), run, NULL);
    conn_t c;
    int st = connect_open(&c, fd, PIN, 0, 0, spki, "m3.test");
    CHECK(st == ESTABLISHED, "established");
    // Plain steps on nothing (tickets, if any), then all the records at once
    for (int i = 0; i < 3; i++) pump_step(&c, 0, NULL, 0);
    int base = c.ptlen;
    c.socklen = 0;
    gather(&c, 1000, 150, sizeof(c.sock));
    int want = queued ? 1300 : 100;
    int ctin = c.socklen;
    step_r *r = pump_step(&c, 0, NULL, 0);
    CHECK(r->err == 0 && r->state == ESTABLISHED, "step ok (-0x%x, state %d)", -r->err, r->state);
    if (!queued) {
        CHECK(c.ptlen - base == 100, "%s: the step with 2 warnings + data (%d B ct_in) returns the data (%d)", ver, ctin, c.ptlen - base);
    } else {
        CHECK(c.ptlen - base == 960, "%s: the first step fills its room (%d)", ver, c.ptlen - base);
        pump_step(&c, 0, NULL, 0);
        CHECK(c.ptlen - base == want, "%s: the next ct_in_len-0 step returns the rest and the data (%d of %d)", ver, c.ptlen - base,
              want);
    }
    CHECK(pattern_ok(c.pt + base, c.ptlen - base, 0, SEED_SERVER), "bytes in order");
    close(fd);
    srv_end(2000);
}
static void c_e2_12(void) { e2_case("ver=12", 0); }
static void c_e2_12_queued(void) { e2_case("ver=12", 1); }
static void c_e2_13(void) { e2_case("ver=13", 0); }

/* 5.2 the tag rule: a stale (slot, tag) touches nothing */
static void c_tag_rule(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    uint8_t pin[32] = { 1 };
    CHECK(tls_open(0, 1, PIN, 0, 0, pin, "m3.test").err == 0, "old session (slot 0, tag 1)");
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), "run=echo", NULL);
    conn_t c;
    memset(&c, 0, sizeof(c)); c.fd = fd; c.slot = 0; c.tag = 2;
    CHECK(tls_open(0, 2, PIN, 0, 0, spki, "m3.test").err == 0, "OPEN slot 0 tag 2 takes the slot over");
    CHECK(handshake(&c) == ESTABLISHED, "new session established");
    stats_r before = tls_stats(0, 2);
    CHECK(tls_stats(0, 1).err == E_NOT_FOUND, "the old tag is gone (takeover)");
    uint8_t junk[200];
    memset(junk, 0x17, sizeof(junk));
    step_r *r = tls_step(0, 1, 0, junk, sizeof(junk), NULL, 0);
    CHECK(r->err == E_NOT_FOUND && r->ct_len == 0 && r->pt_len == 0, "stale-tag STEP with ciphertext -> NOT_FOUND, no output");
    r = tls_step(0, 1, NO_READ, NULL, 0, junk, 10);
    CHECK(r->err == E_NOT_FOUND && r->ct_len == 0, "stale-tag STEP with plaintext -> NOT_FOUND");
    CHECK(tls_stats(0, 1).err == E_NOT_FOUND, "stale-tag STATS -> NOT_FOUND");
    close_r cr = tls_close(0, 1);
    CHECK(cr.err == E_NOT_FOUND && cr.ct_len == 0, "stale-tag CLOSE -> NOT_FOUND");
    stats_r after = tls_stats(0, 2);
    CHECK(after.err == 0 && after.ct_in == before.ct_in && after.ct_out == before.ct_out && after.pt_in == before.pt_in &&
          after.pt_out == before.pt_out && after.state == ESTABLISHED, "the live session's counters are unchanged");
    uint8_t msg[50];
    client_pattern(msg, 50, 0);
    pump_step(&c, NO_READ, msg, 50);
    read_pt(&c, 50);
    CHECK(c.ptlen == 50 && pattern_ok(c.pt, 50, 0, SEED_CLIENT), "the live session still echoes (%d)", c.ptlen);
    CHECK(tls_step(1, 2, 0, NULL, 0, NULL, 0)->err == E_NOT_FOUND, "right tag, wrong slot -> NOT_FOUND");
    close(fd);
    srv_end(2000);
}

/* 5.2 other STEP flag bits -> INVALID_ARG, consuming nothing */
static void c_step_flags(void)
{
    uint8_t pin[32] = { 1 };
    CHECK(tls_open(1, 7, PIN, 0, 0, pin, "m3.test").err == 0, "open");
    stats_r s0 = tls_stats(1, 7);
    uint8_t ct[5] = { 0x16, 3, 3, 0, 0 };
    step_r *r = tls_step(1, 7, 0x02, ct, 5, NULL, 0);
    CHECK(r->err == E_INVALID_ARG && r->ct_len == 0 && r->pt_len == 0, "flags 0x02 -> INVALID_ARG (0x%x)", r->err);
    r = tls_step(1, 7, 0x80, NULL, 0, NULL, 0);
    CHECK(r->err == E_INVALID_ARG, "flags 0x80 -> INVALID_ARG");
    stats_r s1 = tls_stats(1, 7);
    CHECK(s1.ct_in == s0.ct_in && s1.ct_out == s0.ct_out, "nothing consumed or produced");
}

/* 5.2 CLOSE carries the close_notify record; the server sees it */
static void c_close_notify(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=13", pki("leaf.chain.pem"), pki("leaf.key"), "run=drain", NULL);
    conn_t c;
    CHECK(connect_open(&c, fd, PIN, 0, 0, spki, "m3.test") == ESTABLISHED, "established");
    for (int i = 0; i < 3; i++) pump_step(&c, 0, NULL, 0);
    close_r r = tls_close(0, 1);
    CHECK(r.err == 0 && r.ct_len >= 20 && r.ct_len <= 64, "CLOSE ok with the close_notify record (%d B)", r.ct_len);
    send(fd, r.data, r.ct_len, 0);
    shutdown(fd, SHUT_WR);
    srv_end(3000);
    close(fd);
    CHECK(log_has("RX close_notify") == 1, "the server received close_notify");
    CHECK(tls_close(0, 1).err == E_NOT_FOUND, "a second CLOSE -> NOT_FOUND");
    CHECK(tls_stats(0xFF, 0).sessions == 0, "no session left");
    uint8_t pin[32] = { 1 };
    CHECK(tls_open(1, 9, PIN, 0, 0, pin, "m3.test").err == 0, "a session that never handshakes");
    CHECK(tls_step(1, 9, 0, NULL, 0, NULL, 0)->ct_len > 0, "its ClientHello is out");
    CHECK(tls_step(1, 9, 0, NULL, 0, NULL, 0)->ct_len == 0, "nothing more pending");
    r = tls_close(1, 9);
    CHECK(r.err == 0 && r.ct_len == 0, "CLOSE while handshaking: ok, no close_notify (%d B)", r.ct_len);
}

/* 5.2 CLOSE_ALL frees every session and the CA */
static void c_close_all(void)
{
    uint8_t pin[32] = { 1 }, der[2048];
    int n = load("ca.der", der, sizeof(der));
    CHECK(tls_set_ca(der, n, 5).err == 0, "CA");
    CHECK(tls_open(0, 1, PIN, 0, 0, pin, "m3.test").err == 0, "slot 0");
    CHECK(tls_open(1, 2, CUSTOM, 0, 5, NULL, "m3.test").err == 0, "slot 1");
    CHECK(tls_stats(0xFF, 0).sessions == 2, "two sessions");
    CHECK(tls_close_all() == 0, "CLOSE_ALL ok");
    CHECK(tls_stats(0xFF, 0).sessions == 0, "none left");
    CHECK(tls_stats(0, 1).err == E_NOT_FOUND && tls_stats(1, 2).err == E_NOT_FOUND, "both gone");
    CHECK(tls_open(1, 3, CUSTOM, 0, 5, NULL, "m3.test").reason == 3, "the CA is gone");
}

/* A fatal alert after the handshake: FAILED, alert_in set, alert_out none (encrypted) */
static void c_fatal_alert(void)
{
    uint8_t spki[32];
    load("leaf.spki", spki, 32);
    int fd = srv_start("tls", "ver=12", pki("leaf.chain.pem"), pki("leaf.key"), "run=sleep:200,fa:20", NULL);
    conn_t c;
    CHECK(connect_open(&c, fd, PIN, 0, 0, spki, "m3.test") == ESTABLISHED, "established");
    for (int i = 0; i < 40 && c.state == ESTABLISHED; i++) {
        if (c.socklen == 0) gather(&c, 50, 20, sizeof(c.sock));
        pump_step(&c, 0, NULL, 0);
    }
    CHECK(c.state == FAILED && c.r.fail_reason == 0 && c.r.alert_in == 20, "FAILED, alert_in 20 (%d, %d)", c.state, c.r.alert_in);
    CHECK(c.r.err == -0x7780, "esp_err FATAL_ALERT_MESSAGE (-0x%x)", -c.r.err);
    CHECK(c.r.alert_out == 0xFF, "alert_out none (%d)", c.r.alert_out);
    close(fd);
    srv_end(2000);
}

typedef struct { const char *name; void (*fn)(void); int net; } tcase_t;
static const tcase_t cases[] = {
    { "task", c_task, 0 }, { "queue_full", c_queue_full, 0 }, { "block_max", c_block_max, 0 }, { "sizes", c_sizes, 0 },
    { "open_args", c_open_args, 0 }, { "no_entropy", c_no_entropy, 0 }, { "no_time", c_no_time, 0 },
    { "pin_accept13", c_pin_accept13, 1 }, { "pin_accept12", c_pin_accept12, 1 }, { "pin_mismatch", c_pin_mismatch, 1 },
    { "pin_sni", c_pin_sni, 1 }, { "pin_name_ignored", c_pin_name_ignored, 1 }, { "pin_eku", c_pin_eku, 1 },
    { "custom_expired", c_custom_expired, 1 },
    { "custom_accept", c_custom_accept, 1 }, { "custom_catag", c_custom_catag, 0 }, { "custom_untrusted", c_custom_untrusted, 1 },
    { "custom_ca_replaced", c_custom_ca_replaced, 1 }, { "set_ca_rejects", c_set_ca_rejects, 0 },
    { "bundle_accept", c_bundle_accept, 1 }, { "bundle_unknown_root", c_bundle_unknown_root, 1 }, { "bundle_name", c_bundle_name, 1 },
    { "hs13_x25519", c_hs13_x25519, 1 }, { "hs13_hrr_p256", c_hs13_hrr_p256, 1 }, { "hs13_hrr_p384", c_hs13_hrr_p384, 1 },
    { "hs12_p256", c_hs12_p256, 1 }, { "hs12_x25519", c_hs12_x25519, 1 }, { "hs12_p521", c_hs12_p521, 1 },
    { "client_hello", c_client_hello, 1 },
    { "require13_vs_12", c_require13_vs_12, 1 }, { "sentinel", c_sentinel, 1 }, { "sentinel_require13", c_sentinel_require13, 1 },
    { "version_below_12", c_version_below_12, 1 }, { "sh12_bad_suite", c_sh12_bad_suite, 1 }, { "alert70", c_alert70, 1 },
    { "peer_closed", c_peer_closed, 1 }, { "no_ems", c_no_ems, 1 },
    { "established_no_pt", c_established_no_pt, 1 }, { "e1_no_read", c_e1_no_read, 1 },
    { "e2_12", c_e2_12, 1 }, { "e2_12_queued", c_e2_12_queued, 1 }, { "e2_13", c_e2_13, 1 },
    { "tag_rule", c_tag_rule, 1 }, { "step_flags", c_step_flags, 0 }, { "close_notify", c_close_notify, 1 },
    { "close_all", c_close_all, 0 }, { "fatal_alert", c_fatal_alert, 1 },
};

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    int total = 0, failed = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int want = argc < 2;
        for (int a = 1; a < argc; a++) want |= !strcmp(argv[a], cases[i].name);
        if (!want) continue;
        total++;
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            cur_case = cases[i].name;
            case_index = (int)i;
            fake_now = real_now();
            g_unix_time = (uint32_t)fake_now;
            start_dispatch(NULL);
            printf("CASE %s\n", cur_case);
            cases[i].fn();
            if (srv_pid) srv_end(0);
            printf("%s %s (%d of %d checks failed)\n", fails ? "FAIL" : "PASS", cur_case, fails, checks);
            fflush(stdout);
            _exit(fails ? 1 : 0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) printf("FAIL %s (crashed: signal %d)\n", cases[i].name, WTERMSIG(status));
        if (!WIFEXITED(status) || WEXITSTATUS(status)) failed++;
    }
    printf("SUMMARY %d of %d cases failed\n", failed, total);
    return failed ? 1 : 0;
}
