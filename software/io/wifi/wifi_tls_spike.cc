/*
 * wifi_tls_spike.cc
 *
 * SPIKE CODE, NOT FOR RELEASE (esp-tls M2). Measures a TLS session that runs
 * on the WiFi module while this side carries its ciphertext over a TCP socket:
 * connect, handshake, echo, close. Built only with TLS_SPIKE, and reached
 * only through PUT /v1/machine:tlsspike.
 *
 * Every wait has a deadline. Whatever happens, the session is closed if it is
 * still open on the module, and then the socket is closed if it was opened;
 * wifi_tls_spike is the only place that does either, after spike_run has
 * returned.
 */

#ifdef TLS_SPIKE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "rtc.h"
#include "sntp_time.h"
#include "wifi_tls.h"

#define CONNECT_TIMEOUT_MS   5000
#define HANDSHAKE_TIMEOUT_MS 15000
#define ECHO_TIMEOUT_MS      15000
#define SEND_TIMEOUT_MS      5000
#define RECV_POLL_MS         100
#define UNSENT_RETRIES       10   // 50 ms apart: GET_RANDOM holds the channel for up to 200 ms
#define ECHO_CHUNK           512  // plaintext per step, leaving room for ciphertext coming in
#define OUT_ROOM             1536 // more than a reply can carry
#define EARLIEST_TIME        1735689600u // 2025-01-01: a clock before this has not been set
#define ESP_ERR_NOT_FOUND    0x105 // esp_err.h: CLOSE of a session the module no longer has

typedef struct {
    int sock;
    bool session_open; // on the module: opened, and not yet ended by it or closed
    uint8_t session;
    uint8_t *in;     // ciphertext from the server, WIFI_TLS_STEP_MAX_IN
    uint8_t *pt_in;  // plaintext to the server, ECHO_CHUNK
    uint8_t *ct_out; // OUT_ROOM
    uint8_t *pt_out; // OUT_ROOM
} spike_t;

uint8_t wifi_tls_spike_payload(uint32_t seed, uint32_t i)
{
    return (uint8_t)(((uint32_t)(seed + i) * 2654435761u) >> 24);
}

// Decimal digits and nothing else, one at least, no larger than limit.
static bool parse_decimal(const char *text, uint32_t limit, uint32_t *value)
{
    if ((text == NULL) || (*text == '\0')) {
        return false;
    }
    uint32_t parsed = 0;
    for (const char *p = text; *p; p++) {
        if ((*p < '0') || (*p > '9')) {
            return false;
        }
        uint32_t digit = *p - '0';
        if ((digit > limit) || (parsed > (limit - digit) / 10)) {
            return false;
        }
        parsed = (parsed * 10) + digit;
    }
    *value = parsed;
    return true;
}

// Four decimal numbers 0-255 with a dot between, and nothing else. Stricter
// than inet_aton, which also takes hexadecimal, octal and fewer parts.
static bool dotted_ipv4(const char *text)
{
    if (text == NULL) {
        return false;
    }
    char part[4];
    for (int n = 0; n < 4; n++) {
        int len = 0;
        while ((*text >= '0') && (*text <= '9') && (len < 3)) {
            part[len++] = *text++;
        }
        part[len] = '\0';
        uint32_t value;
        if (!parse_decimal(part, 255, &value) || (*text != ((n < 3) ? '.' : '\0'))) {
            return false;
        }
        text++;
    }
    return true;
}

const char *wifi_tls_spike_parse(const char *host, const char *port, const char *sni, const char *verify,
                                 const char *ca, const char *echo, const char *seed, wifi_tls_spike_args_t *args)
{
    uint32_t port_value, verify_value = 1, echo_value = 0, seed_value = 0;
    uint8_t flags;
    if (!dotted_ipv4(host)) {
        return "host";
    }
    if (!parse_decimal(port, 65535, &port_value) || (port_value == 0)) {
        return "port";
    }
    if (sni && (strlen(sni) > WIFI_TLS_MAX_SNI)) {
        return "sni";
    }
    if (verify && !parse_decimal(verify, 1, &verify_value)) {
        return "verify";
    }
    // The module refuses to verify without a name to check the certificate
    // against (ESP_ERR_INVALID_ARG), so do not open a socket to find that out.
    if (verify_value && (!sni || !*sni)) {
        return "sni (verify=1 needs a server name; give sni, or verify=0)";
    }
    if (!ca || !strcmp(ca, "test")) {
        flags = WIFI_TLS_FLAG_TEST_CA;
    } else if (!strcmp(ca, "bundle")) {
        flags = WIFI_TLS_FLAG_CA_BUNDLE;
    } else if (!strcmp(ca, "none")) {
        flags = 0;
    } else {
        return "ca";
    }
    if (echo && !parse_decimal(echo, WIFI_TLS_SPIKE_MAX_ECHO, &echo_value)) {
        return "echo";
    }
    if (seed && !parse_decimal(seed, 0xFFFFFFFFu, &seed_value)) {
        return "seed";
    }
    args->host = host;
    args->port = (uint16_t)port_value;
    args->sni = sni ? sni : "";
    args->flags = flags | (verify_value ? WIFI_TLS_FLAG_VERIFY : 0);
    args->echo = (int)echo_value;
    args->seed = seed_value;
    return NULL;
}

static const char *code_name(int code)
{
    switch (code) {
        case WIFI_TLS_BUSY:      return "no answer in time";
        case WIFI_TLS_REFUSED:   return "refused";
        case WIFI_TLS_INVALID:   return "malformed answer";
        case WIFI_TLS_NO_MODULE: return "module application not running";
        case WIFI_TLS_UNSENT:    return "could not be sent";
        case WIFI_TLS_TOO_LONG:  return "request too long";
        case WIFI_TLS_AGAIN:     return "input not taken";
        default:                 return "error";
    }
}

static const char *state_name(int state)
{
    switch (state) {
        case WIFI_TLS_HANDSHAKING: return "HANDSHAKING";
        case WIFI_TLS_ESTABLISHED: return "ESTABLISHED";
        case WIFI_TLS_CLOSED:      return "CLOSED";
        case WIFI_TLS_FAILED:      return "FAILED";
        default:                   return "unknown";
    }
}

// Ends the run at detail, whose prefix names the stage it belongs to.
static bool fail(wifi_tls_spike_result_t *r, const char *detail, int code, const char *fmt, ...)
{
    static const char *const stages[] = { "open", "handshake", "echo", "close" };
    r->stage = "connect"; // host, memory, socket, connect and socket_options
    for (unsigned i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        if (strncmp(detail, stages[i], strlen(stages[i])) == 0) {
            r->stage = stages[i];
        }
    }
    r->detail = detail;
    r->code = code;
    int n = snprintf(r->error, sizeof(r->error), "%s: ", detail);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->error + n, sizeof(r->error) - n, fmt, ap);
    va_end(ap);
    return false;
}

static bool fail_call(wifi_tls_spike_result_t *r, const char *detail, int code)
{
    if (r->esp_err) {
        return fail(r, detail, code, "%s (%d), esp_err %d", code_name(code), code, r->esp_err);
    }
    return fail(r, detail, code, "%s (%d)", code_name(code), code);
}

static bool fail_errno(wifi_tls_spike_result_t *r, const char *detail, int error)
{
    return fail(r, detail, error, "%s (errno %d)", strerror(error), error);
}

static bool fail_state(wifi_tls_spike_result_t *r, const char *detail, int state)
{
    return fail(r, detail, state, "session %s, esp_err %d", state_name(state), r->esp_err);
}

static bool expired(TickType_t start, uint32_t limit_ms)
{
    return (xTaskGetTickCount() - start) >= pdMS_TO_TICKS(limit_ms);
}

// UTC from this side's clocks: SNTP's when it has answered, otherwise the RTC
// chip's, which keeps local time (Rtc::set_time_utc), so mktime and TZ turn it
// back. 0 when neither has a plausible time.
static uint32_t nios_unix_time(const char **source)
{
    uint32_t now = sntp_utc_now();
    if (now >= EARLIEST_TIME) {
        *source = "sntp";
        return now;
    }
    if (rtc.is_valid()) {
        int y, M, D, wd, h, m, s;
        rtc.get_time(y, M, D, wd, h, m, s);
        struct tm t;
        memset(&t, 0, sizeof(t));
        t.tm_year = y + 80; // the chip counts from 1980
        t.tm_mon = M - 1;
        t.tm_mday = D;
        t.tm_hour = h;
        t.tm_min = m;
        t.tm_sec = s;
        t.tm_isdst = -1;
        time_t utc = mktime(&t);
        if ((utc != (time_t)-1) && ((uint32_t)utc >= EARLIEST_TIME)) {
            *source = "rtc";
            return (uint32_t)utc;
        }
    }
    *source = "none";
    return 0;
}

// Nothing is sent on UNSENT, so the same request can simply go again. A step
// that ends the session on the module frees it there.
static int step(spike_t *s, wifi_tls_step_t *st, wifi_tls_spike_result_t *r)
{
    int result;
    for (int i = 0; ; i++) {
        TickType_t sent = xTaskGetTickCount();
        result = wifi_tls_step(s->session, st);
        uint32_t ms = (xTaskGetTickCount() - sent) * portTICK_PERIOD_MS;
        if (ms > r->step_max_ms) {
            r->step_max_ms = ms;
        }
        if ((result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    r->steps++;
    if (st->state != WIFI_TLS_UNKNOWN) {
        r->state = st->state;
        if ((st->state == WIFI_TLS_FAILED) || (st->state == WIFI_TLS_CLOSED)) {
            s->session_open = false;
        }
    }
    r->esp_err = st->esp_err;
    return result;
}

static int stats(uint8_t session, wifi_tls_stats_t *out, bool *have, wifi_tls_spike_result_t *r)
{
    int esp_err;
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_stats(session, out, &esp_err);
        if ((result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    *have = (result == 0);
    if (result) {
        r->stats_error = result;
    }
    return result;
}

// Sends all of it before the deadline, or returns an errno.
static int send_all(int sock, const uint8_t *data, int length, uint32_t *counter)
{
    TickType_t start = xTaskGetTickCount();
    while (length > 0) {
        int sent = lwip_send(sock, data, length, 0);
        if (sent <= 0) {
            return (sent < 0) ? errno : EPIPE;
        }
        *counter += sent;
        data += sent;
        length -= sent;
        if ((length > 0) && expired(start, SEND_TIMEOUT_MS)) {
            return ETIMEDOUT;
        }
    }
    return 0;
}

// Reads what the server has sent. With wait false it returns at once;
// otherwise it waits until the deadline for at least one byte. Returns the
// number of bytes, 0 when there are none yet, or -1 with *error set: EPIPE
// when the server has closed, ETIMEDOUT at the deadline.
static int receive(int sock, uint8_t *buf, int room, bool wait, TickType_t start, uint32_t limit_ms, int *error)
{
    while (true) {
        int n = lwip_recv(sock, buf, room, wait ? 0 : MSG_DONTWAIT);
        if (n > 0) {
            return n;
        }
        if (n == 0) {
            *error = EPIPE;
            return -1;
        }
        if ((errno != EWOULDBLOCK) && (errno != EAGAIN)) {
            *error = errno;
            return -1;
        }
        if (!wait) {
            return 0;
        }
        if (expired(start, limit_ms)) {
            *error = ETIMEDOUT;
            return -1;
        }
    }
}

// A non blocking connect, polled: lwIP answers EALREADY while it is under
// way and EISCONN once it is done. The socket is left blocking again, as
// receive expects. Returns 0 or an errno.
static int connect_within(int sock, struct sockaddr_in *addr)
{
    int on = 1;
    int off = 0;
    int error = 0;
    if (lwip_ioctl(sock, FIONBIO, &on) < 0) {
        return errno;
    }
    TickType_t start = xTaskGetTickCount();
    while (lwip_connect(sock, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
        error = errno;
        if (error == EISCONN) {
            error = 0;
            break;
        }
        if ((error != EINPROGRESS) && (error != EALREADY)) {
            break;
        }
        if (expired(start, CONNECT_TIMEOUT_MS)) {
            error = ETIMEDOUT;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if ((lwip_ioctl(sock, FIONBIO, &off) < 0) && !error) {
        error = errno;
    }
    return error;
}

// Runs the spike up to the point where it ends, and returns whether it
// succeeded. It opens the socket and the session but closes neither: every
// return below leaves that to wifi_tls_spike.
static bool spike_run(spike_t *s, const char *host, uint16_t port, const char *sni, uint8_t flags, int echo,
                      uint32_t seed, wifi_tls_spike_result_t *r)
{
    int error = 0;

    stats(WIFI_TLS_SESSION_GLOBAL, &r->before, &r->have_before, r);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(port);
    if (!inet_aton(host, &addr.sin_addr)) {
        return fail(r, "host", EINVAL, "not a dotted IPv4 address");
    }

    s->in = (uint8_t *)malloc(WIFI_TLS_STEP_MAX_IN + ECHO_CHUNK + 2 * OUT_ROOM);
    if (!s->in) {
        return fail_errno(r, "memory", ENOMEM);
    }
    s->pt_in = s->in + WIFI_TLS_STEP_MAX_IN;
    s->ct_out = s->pt_in + ECHO_CHUNK;
    s->pt_out = s->ct_out + OUT_ROOM;

    s->sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock < 0) {
        return fail_errno(r, "socket", errno);
    }
    r->socket_opened = true;
    error = connect_within(s->sock, &addr);
    if (error) {
        return fail_errno(r, "connect", error);
    }
    // Without these a receive or a send could wait for ever.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_POLL_MS * 1000;
    if (lwip_setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return fail_errno(r, "socket_options", errno);
    }
    tv.tv_sec = SEND_TIMEOUT_MS / 1000;
    tv.tv_usec = 0;
    if (lwip_setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return fail_errno(r, "socket_options", errno);
    }

    // The handshake, timed from OPEN to ESTABLISHED.
    r->unix_time = nios_unix_time(&r->nios_clock);
    TickType_t start = xTaskGetTickCount();
    int result;
    uint8_t reason = 0;
    for (int i = 0; ; i++) {
        result = wifi_tls_open(flags, sni, r->unix_time, &s->session, &r->esp_err, &reason);
        if ((result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    // All of OPEN, retries included, so that handshake_ms - open_ms is the
    // steps alone; on a failed OPEN too.
    r->open_ms = (xTaskGetTickCount() - start) * portTICK_PERIOD_MS;
    if (result) {
        // After BUSY the module may have opened a session all the same, and
        // this side cannot name it to close it; the module evicts the least
        // recently used session when an OPEN finds its table full.
        if ((result == WIFI_TLS_REFUSED) && (reason == WIFI_TLS_REASON_NO_TIME)) {
            return fail(r, "open", result, "verify needs a trustworthy time, and neither the Ultimate (clock: %s) "
                        "nor the module has one (ESP_ERR_INVALID_STATE)", r->nios_clock);
        }
        if ((result == WIFI_TLS_REFUSED) && (reason == WIFI_TLS_REASON_NO_ENTROPY)) {
            return fail(r, "open", result, "no entropy source: the module's radio has not started "
                        "(ESP_ERR_INVALID_STATE)");
        }
        return fail_call(r, "open", result);
    }
    s->session_open = true;
    r->session_opened = true;
    r->state = WIFI_TLS_HANDSHAKING;
    // The module's clock and its source, from the session itself, while it
    // is sure to exist: a handshake that fails frees it. Not part of the
    // handshake time.
    TickType_t asked = xTaskGetTickCount();
    stats(s->session, &r->opened, &r->have_opened, r);
    start += xTaskGetTickCount() - asked;

    wifi_tls_step_t st;
    memset(&st, 0, sizeof(st));
    st.ct_in = s->in;
    st.pt_in = s->pt_in;
    st.ct_out = s->ct_out;
    st.ct_out_room = OUT_ROOM;
    st.pt_out = s->pt_out;
    st.pt_out_room = OUT_ROOM;

    // A step answered AGAIN did not take its input, which then goes again as it is.
    int in_len = 0;
    while (true) {
        st.ct_in_len = in_len;
        st.pt_in_len = 0;
        result = step(s, &st, r);
        r->handshake_steps++;
        bool resend = (result == WIFI_TLS_AGAIN);
        if (resend) {
            r->resends++;
        } else if (result) {
            return fail_call(r, "handshake_step", result);
        } else {
            in_len = 0;
        }
        // The alert of a failed handshake goes to the server too.
        error = send_all(s->sock, st.ct_out, st.ct_out_len, &r->tcp_out);
        if (error) {
            return fail_errno(r, "handshake_send", error);
        }
        r->early_plaintext += st.pt_out_len;
        if (st.state == WIFI_TLS_ESTABLISHED) {
            if (!resend) {
                break;
            }
        } else if (st.state != WIFI_TLS_HANDSHAKING) {
            return fail_state(r, "handshake_state", st.state);
        }
        if (!resend) {
            // After a step that had something to say, step again at once: there
            // may be more than one reply could carry. Otherwise wait for the server.
            bool more = (st.ct_out_len != 0) || (st.pt_out_len != 0);
            in_len = receive(s->sock, s->in, WIFI_TLS_STEP_MAX_IN, !more, start, HANDSHAKE_TIMEOUT_MS, &error);
            if (in_len < 0) {
                return fail_errno(r, "handshake_recv", error);
            }
            r->tcp_in += in_len;
        }
        if (expired(start, HANDSHAKE_TIMEOUT_MS)) {
            return fail_errno(r, "handshake_timeout", ETIMEDOUT);
        }
    }
    r->handshake_ms = (xTaskGetTickCount() - start) * portTICK_PERIOD_MS;
    stats(s->session, &r->peak, &r->have_peak, r);

    // The echo: the payload out in chunks, and the same bytes back.
    start = xTaskGetTickCount();
    bool more = false;
    bool resend = false;
    int chunk = 0;
    while (r->echo_received < echo) {
        if (!resend) {
            chunk = echo - r->echo_sent;
            if (chunk > ECHO_CHUNK) {
                chunk = ECHO_CHUNK;
            }
            for (int i = 0; i < chunk; i++) {
                s->pt_in[i] = wifi_tls_spike_payload(seed, r->echo_sent + i);
            }
            // Wait for the server only when there is nothing left to send and the
            // module had nothing more to say.
            bool wait = (chunk == 0) && !more;
            in_len = receive(s->sock, s->in, WIFI_TLS_STEP_MAX_IN - chunk, wait, start, ECHO_TIMEOUT_MS, &error);
            if (in_len < 0) {
                return fail_errno(r, "echo_recv", error);
            }
            r->tcp_in += in_len;
        }

        st.ct_in_len = in_len;
        st.pt_in_len = chunk;
        result = step(s, &st, r);
        resend = (result == WIFI_TLS_AGAIN);
        if (resend) {
            r->resends++;
        } else if (result) {
            return fail_call(r, "echo_step", result);
        } else {
            r->echo_sent += chunk; // the step took all of pt_in
        }
        error = send_all(s->sock, st.ct_out, st.ct_out_len, &r->tcp_out);
        if (error) {
            return fail_errno(r, "echo_send", error);
        }
        for (int i = 0; i < st.pt_out_len; i++) {
            if ((r->echo_received + i >= echo) ||
                    (s->pt_out[i] != wifi_tls_spike_payload(seed, r->echo_received + i))) {
                r->echo_received += i;
                return fail(r, "echo_compare", 0, "byte %d of the echo differs from what was sent",
                            r->echo_received);
            }
        }
        r->echo_received += st.pt_out_len;
        if (st.state != WIFI_TLS_ESTABLISHED) {
            return fail_state(r, "echo_state", st.state);
        }
        more = (st.ct_out_len != 0) || (st.pt_out_len != 0);
        if (expired(start, ECHO_TIMEOUT_MS)) {
            return fail_errno(r, "echo_timeout", ETIMEDOUT);
        }
    }
    r->echo_ok = true;
    r->stage = "done";
    r->detail = "done";
    return true;
}

void wifi_tls_spike(const char *host, uint16_t port, const char *sni, uint8_t flags, int echo, uint32_t seed,
                    wifi_tls_spike_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->state = -1;
    r->nios_clock = "none";
    spike_t s;
    memset(&s, 0, sizeof(s));
    s.sock = -1;

    r->ok = spike_run(&s, host, port, sni, flags, echo, seed, r);

    if (s.session_open) {
        int esp_err;
        for (int i = 0; ; i++) {
            r->close_result = wifi_tls_close(s.session, &esp_err);
            if ((r->close_result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        if ((r->close_result == WIFI_TLS_REFUSED) && (esp_err == ESP_ERR_NOT_FOUND)) {
            r->close_result = 0; // the module had ended it already
        }
        if (r->close_result && r->ok) {
            r->ok = false;
            r->esp_err = esp_err;
            fail_call(r, "close", r->close_result);
        }
    }
    if (s.sock >= 0) {
        lwip_close(s.sock);
    }
    free(s.in);
    stats(WIFI_TLS_SESSION_GLOBAL, &r->after, &r->have_after, r);
}

#endif
