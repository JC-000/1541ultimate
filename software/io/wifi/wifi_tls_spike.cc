/*
 * wifi_tls_spike.cc
 *
 * SPIKE CODE, NOT FOR RELEASE (esp-tls M2). Measures a TLS session that runs
 * on the WiFi module while this side carries its ciphertext over a TCP socket:
 * connect, handshake, echo, close. Built only with TLS_SPIKE, and reached
 * only through PUT /v1/machine:tlsspike.
 *
 * Every wait has a deadline. Whatever happens, the session is closed if it
 * was opened, and then the socket is closed if it was opened; wifi_tls_spike
 * is the only place that does either, after spike_run has returned.
 */

#ifdef TLS_SPIKE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "wifi_tls.h"

#define CONNECT_TIMEOUT_MS   5000
#define HANDSHAKE_TIMEOUT_MS 15000
#define ECHO_TIMEOUT_MS      15000
#define SEND_TIMEOUT_MS      5000
#define RECV_POLL_MS         100
#define UNSENT_RETRIES       10   // 50 ms apart: GET_RANDOM holds the channel for up to 200 ms
#define ECHO_CHUNK           512  // plaintext per step, leaving room for ciphertext coming in
#define OUT_ROOM             1536 // more than a reply can carry

typedef struct {
    int sock;
    bool session_open;
    uint8_t session;
    uint8_t *in;     // ciphertext from the server, WIFI_TLS_STEP_MAX_IN
    uint8_t *pt_in;  // plaintext to the server, ECHO_CHUNK
    uint8_t *ct_out; // OUT_ROOM
    uint8_t *pt_out; // OUT_ROOM
} spike_t;

// The echo bytes: no period of 256, so that a shifted or repeated block shows.
static uint8_t pattern(int i)
{
    return (uint8_t)((i * 7) + (i >> 8) + 0x21);
}

static bool fail(wifi_tls_spike_result_t *r, const char *stage, int error)
{
    r->stage = stage;
    r->error = error;
    return false;
}

static bool expired(TickType_t start, uint32_t limit_ms)
{
    return (xTaskGetTickCount() - start) >= pdMS_TO_TICKS(limit_ms);
}

// Nothing is sent on UNSENT, so the same request can simply go again.
static int step(spike_t *s, wifi_tls_step_t *st, wifi_tls_spike_result_t *r)
{
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_step(s->session, st);
        if ((result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    r->steps++;
    if (st->state != WIFI_TLS_UNKNOWN) {
        r->state = st->state;
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
                      wifi_tls_spike_result_t *r)
{
    int error = 0;

    stats(WIFI_TLS_SESSION_GLOBAL, &r->before, &r->have_before, r);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(port);
    if (!inet_aton(host, &addr.sin_addr)) {
        return fail(r, "host", EINVAL);
    }

    s->in = (uint8_t *)malloc(WIFI_TLS_STEP_MAX_IN + ECHO_CHUNK + 2 * OUT_ROOM);
    if (!s->in) {
        return fail(r, "memory", ENOMEM);
    }
    s->pt_in = s->in + WIFI_TLS_STEP_MAX_IN;
    s->ct_out = s->pt_in + ECHO_CHUNK;
    s->pt_out = s->ct_out + OUT_ROOM;

    s->sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock < 0) {
        return fail(r, "socket", errno);
    }
    r->socket_opened = true;
    error = connect_within(s->sock, &addr);
    if (error) {
        return fail(r, "connect", error);
    }
    // Without these a receive or a send could wait for ever.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_POLL_MS * 1000;
    if (lwip_setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return fail(r, "socket_options", errno);
    }
    tv.tv_sec = SEND_TIMEOUT_MS / 1000;
    tv.tv_usec = 0;
    if (lwip_setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return fail(r, "socket_options", errno);
    }

    // The handshake, timed from OPEN to ESTABLISHED.
    TickType_t start = xTaskGetTickCount();
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_open(flags, sni, &s->session, &r->esp_err);
        if ((result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (result) {
        // After BUSY the module may have opened a session all the same, and
        // this side cannot name it to close it.
        return fail(r, "open", result);
    }
    s->session_open = true;
    r->session_opened = true;
    r->state = WIFI_TLS_HANDSHAKING;

    wifi_tls_step_t st;
    memset(&st, 0, sizeof(st));
    st.ct_in = s->in;
    st.pt_in = s->pt_in;
    st.ct_out = s->ct_out;
    st.ct_out_room = OUT_ROOM;
    st.pt_out = s->pt_out;
    st.pt_out_room = OUT_ROOM;

    int in_len = 0;
    while (true) {
        st.ct_in_len = in_len;
        st.pt_in_len = 0;
        result = step(s, &st, r);
        r->handshake_steps++;
        in_len = 0;
        if (result) {
            return fail(r, "handshake_step", result);
        }
        // The alert of a failed handshake goes to the server too.
        error = send_all(s->sock, st.ct_out, st.ct_out_len, &r->tcp_out);
        if (error) {
            return fail(r, "handshake_send", error);
        }
        r->early_plaintext += st.pt_out_len;
        if (st.state == WIFI_TLS_ESTABLISHED) {
            break;
        }
        if (st.state != WIFI_TLS_HANDSHAKING) {
            return fail(r, "handshake_state", st.state);
        }
        // After a step that had something to say, step again at once: there
        // may be more than one reply could carry. Otherwise wait for the server.
        bool more = (st.ct_out_len != 0) || (st.pt_out_len != 0);
        in_len = receive(s->sock, s->in, WIFI_TLS_STEP_MAX_IN, !more, start, HANDSHAKE_TIMEOUT_MS, &error);
        if (in_len < 0) {
            return fail(r, "handshake_recv", error);
        }
        r->tcp_in += in_len;
        if (expired(start, HANDSHAKE_TIMEOUT_MS)) {
            return fail(r, "handshake_timeout", ETIMEDOUT);
        }
    }
    r->handshake_ms = (xTaskGetTickCount() - start) * portTICK_PERIOD_MS;
    stats(s->session, &r->peak, &r->have_peak, r);

    // The echo: plaintext out in chunks, and the same bytes back.
    start = xTaskGetTickCount();
    bool more = false;
    bool mismatch = false;
    while (r->echo_received < echo) {
        int chunk = echo - r->echo_sent;
        if (chunk > ECHO_CHUNK) {
            chunk = ECHO_CHUNK;
        }
        for (int i = 0; i < chunk; i++) {
            s->pt_in[i] = pattern(r->echo_sent + i);
        }
        // Wait for the server only when there is nothing left to send and the
        // module had nothing more to say.
        bool wait = (chunk == 0) && !more;
        in_len = receive(s->sock, s->in, WIFI_TLS_STEP_MAX_IN - chunk, wait, start, ECHO_TIMEOUT_MS, &error);
        if (in_len < 0) {
            return fail(r, "echo_recv", error);
        }
        r->tcp_in += in_len;

        st.ct_in_len = in_len;
        st.pt_in_len = chunk;
        result = step(s, &st, r);
        if (result) {
            return fail(r, "echo_step", result);
        }
        r->echo_sent += chunk; // a step takes all of pt_in
        error = send_all(s->sock, st.ct_out, st.ct_out_len, &r->tcp_out);
        if (error) {
            return fail(r, "echo_send", error);
        }
        for (int i = 0; i < st.pt_out_len; i++) {
            if ((r->echo_received + i >= echo) || (s->pt_out[i] != pattern(r->echo_received + i))) {
                mismatch = true;
            }
        }
        r->echo_received += st.pt_out_len;
        if (mismatch) {
            return fail(r, "echo_compare", 0);
        }
        if (st.state != WIFI_TLS_ESTABLISHED) {
            return fail(r, "echo_state", st.state);
        }
        more = (st.ct_out_len != 0) || (st.pt_out_len != 0);
        if (expired(start, ECHO_TIMEOUT_MS)) {
            return fail(r, "echo_timeout", ETIMEDOUT);
        }
    }
    r->echo_ok = true;
    r->stage = "done";
    return true;
}

void wifi_tls_spike(const char *host, uint16_t port, const char *sni, uint8_t flags, int echo,
                    wifi_tls_spike_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->state = -1;
    spike_t s;
    memset(&s, 0, sizeof(s));
    s.sock = -1;

    r->ok = spike_run(&s, host, port, sni, flags, echo, r);

    if (s.session_open) {
        int esp_err;
        for (int i = 0; ; i++) {
            r->close_result = wifi_tls_close(s.session, &esp_err);
            if ((r->close_result != WIFI_TLS_UNSENT) || (i == UNSENT_RETRIES)) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        if (r->close_result) {
            r->ok = false;
            if (!r->stage || !strcmp(r->stage, "done")) {
                r->stage = "close";
                r->error = r->close_result;
                r->esp_err = esp_err;
            }
        }
    }
    if (s.sock >= 0) {
        lwip_close(s.sock);
    }
    free(s.in);
    stats(WIFI_TLS_SESSION_GLOBAL, &r->after, &r->have_after, r);
}

#endif
