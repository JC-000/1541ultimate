/*
 * The exits of the TLS spike (software/io/wifi/wifi_tls_spike.cc).
 *
 * The real spike runs against a fake socket layer, a fake module and a fake
 * server that together complete a handshake and echo the plaintext back. A
 * clean run counts the calls that can fail; then each one is made to fail in
 * turn, in every way it can, and whatever the spike does next is checked:
 * the session is closed exactly when it was opened, the socket exactly when it
 * was created, the buffer is freed, nothing is used after it is closed, every
 * wait ends, and the result says where it stopped.
 */
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <map>
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "wifi_tls.h"

static int failures;
static int checks;

static void check(bool condition, const char *what, ...)
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

// The kinds of call that can fail, and in how many ways.
enum { K_MALLOC, K_SOCKET, K_IOCTL, K_CONNECT, K_SETSOCKOPT, K_OPEN, K_STEP, K_SEND, K_RECV, K_CLOSE, K_STATS, K_COUNT };
static const char *kind_names[K_COUNT] = { "malloc", "socket", "ioctl", "connect", "setsockopt", "open", "step",
                                           "send", "recv", "close", "stats" };
static const int variants[K_COUNT] = { 1, 1, 1, 2, 1, 5, 7, 2, 3, 3, 2 };

static int fail_at;      // the fallible call to fail, counted from 0; -1 for none
static int fail_variant;
static bool persistent;  // the failure repeats on every later call of the same kind
static int persistent_kind;
static int event;        // fallible calls so far
static int failed_kind;

static std::vector<std::string> calls;
static TickType_t now;

// The world behind the calls.
static const int FD = 7;
static bool sock_open, connecting;
static int connect_polls;
static bool module_open, module_established;
static int module_steps;
static uint32_t module_ct_seen;   // ciphertext the module has taken from the server during the handshake
static uint32_t server_to_send;   // ciphertext bytes the server has ready
static uint32_t server_echo_owed; // plaintext the server echoes once the client's ciphertext has gone out
static uint32_t echo_owed_next;
static uint32_t echo_returned;
static bool corrupt_echo;
static uint32_t surplus_echo;     // bytes the server sends back beyond what it was sent
static void *allocated;
static int frees;

// Returns whether this fallible call is the one that fails, or keeps failing.
static bool fails(int kind)
{
    if (persistent && (persistent_kind == kind)) {
        return true;
    }
    bool now_fails = (event++ == fail_at);
    if (now_fails) {
        failed_kind = kind;
        calls.push_back(std::string("FAULT ") + kind_names[kind]);
        if (persistent_kind == kind) {
            persistent = true;
        }
    }
    return now_fails;
}

static uint8_t pattern(int i)
{
    return (uint8_t)((i * 7) + (i >> 8) + 0x21); // as the spike's
}

TickType_t xTaskGetTickCount(void)
{
    return ++now;
}

void vTaskDelay(TickType_t ticks)
{
    now += ticks;
}

// The spike's malloc and free, renamed where stdlib.h declares them, so C linkage.
extern "C" void *spike_malloc(size_t n);
extern "C" void spike_free(void *p);

void *spike_malloc(size_t n)
{
    calls.push_back("malloc");
    if (fails(K_MALLOC)) {
        return NULL;
    }
    allocated = malloc(n);
    return allocated;
}

void spike_free(void *p)
{
    calls.push_back("free");
    if (p) {
        if (p != allocated) {
            calls.push_back("FREE OF A STRANGER");
        }
        frees++;
        free(p);
    }
}

int fake_inet_aton(const char *cp, struct in_addr *addr)
{
    if (strcmp(cp, "10.0.0.2") != 0) {
        return 0;
    }
    addr->s_addr = 0x0200000A;
    return 1;
}

int lwip_socket(int domain, int type, int protocol)
{
    calls.push_back("socket");
    if (fails(K_SOCKET)) {
        errno = EMFILE;
        return -1;
    }
    sock_open = true;
    return FD;
}

static bool used_after_close(int s)
{
    if ((s != FD) || !sock_open) {
        calls.push_back("SOCKET USED WHILE CLOSED");
        return true;
    }
    return false;
}

int lwip_ioctl(int s, long cmd, void *argp)
{
    used_after_close(s);
    calls.push_back((*(int *)argp) ? "nonblocking" : "blocking");
    if (fails(K_IOCTL)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int lwip_connect(int s, const struct sockaddr *name, socklen_t_stub namelen)
{
    used_after_close(s);
    calls.push_back("connect");
    if (fails(K_CONNECT)) {
        if (fail_variant == 0) {
            errno = ECONNREFUSED;
        } else {
            persistent = true; // never completes
            persistent_kind = K_CONNECT;
            errno = connecting ? EALREADY : EINPROGRESS;
            connecting = true;
        }
        return -1;
    }
    if (!connecting) {
        connecting = true;
        errno = EINPROGRESS;
        return -1;
    }
    if (connect_polls++ < 2) {
        errno = EALREADY;
        return -1;
    }
    errno = EISCONN;
    return -1;
}

int lwip_setsockopt(int s, int level, int optname, const void *optval, socklen_t_stub optlen)
{
    used_after_close(s);
    calls.push_back("setsockopt");
    if (fails(K_SETSOCKOPT)) {
        errno = ENOPROTOOPT;
        return -1;
    }
    return 0;
}

ssize_t lwip_send(int s, const void *dataptr, size_t size, int flags)
{
    used_after_close(s);
    calls.push_back("send");
    if (fails(K_SEND)) {
        if (fail_variant == 0) {
            errno = ECONNRESET;
            return -1;
        }
        return 0;
    }
    if (!module_established) {
        server_to_send += (module_steps == 1) ? 180 : 0; // the server's flight answers the ClientHello
    }
    if (server_echo_owed) {
        server_echo_owed += surplus_echo;
        surplus_echo = 0;
    }
    server_to_send += server_echo_owed;
    server_echo_owed = 0;
    return size;
}

ssize_t lwip_recv(int s, void *mem, size_t len, int flags)
{
    used_after_close(s);
    calls.push_back((flags & MSG_DONTWAIT) ? "poll" : "recv");
    if (fails(K_RECV)) {
        if (fail_variant == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (fail_variant == 1) {
            return 0; // the server closed
        }
        persistent = true; // the server goes silent
        persistent_kind = K_RECV;
    }
    if (!(persistent && (persistent_kind == K_RECV)) && server_to_send) {
        size_t n = (server_to_send < len) ? server_to_send : len;
        if (n > 700) {
            n = 700;
        }
        server_to_send -= n;
        memset(mem, 0x17, n);
        return n;
    }
    if (!(flags & MSG_DONTWAIT)) {
        now += 20; // SO_RCVTIMEO
    }
    errno = EWOULDBLOCK;
    return -1;
}

int lwip_close(int s)
{
    calls.push_back("closesocket");
    if ((s != FD) || !sock_open) {
        calls.push_back("CLOSE OF A STRANGER");
    }
    sock_open = false;
    return 0;
}

int wifi_tls_open(uint8_t flags, const char *sni, uint8_t *session, int *esp_err)
{
    calls.push_back("open");
    *esp_err = 0;
    if (fails(K_OPEN)) {
        switch (fail_variant) {
            case 0: return WIFI_TLS_BUSY;
            case 1: *esp_err = 0x103; return WIFI_TLS_REFUSED;
            case 2: return WIFI_TLS_INVALID;
            case 3: persistent = true; persistent_kind = K_OPEN; return WIFI_TLS_UNSENT;
            default: return WIFI_TLS_UNSENT; // once: nothing was sent, so it goes again
        }
    }
    module_open = true;
    *session = 1;
    return 0;
}

int wifi_tls_step(uint8_t session, wifi_tls_step_t *st)
{
    calls.push_back("step");
    if (!module_open || (session != 1)) {
        calls.push_back("STEP ON A CLOSED SESSION");
    }
    st->ct_out_len = 0;
    st->pt_out_len = 0;
    st->state = WIFI_TLS_UNKNOWN;
    st->esp_err = 0;
    if ((st->ct_in_len + st->pt_in_len) > WIFI_TLS_STEP_MAX_IN) {
        calls.push_back("STEP TOO LONG");
        return WIFI_TLS_TOO_LONG;
    }
    if (fails(K_STEP)) {
        switch (fail_variant) {
            case 0: return WIFI_TLS_BUSY;
            case 1: st->esp_err = 0x102; st->state = WIFI_TLS_HANDSHAKING; return WIFI_TLS_REFUSED;
            case 2: return WIFI_TLS_INVALID;
            case 3: persistent = true; persistent_kind = K_STEP; return WIFI_TLS_UNSENT;
            case 4: // a failed handshake, or an alert later on
                st->state = WIFI_TLS_FAILED;
                st->esp_err = -0x2700;
                st->ct_out_len = 7;
                return 0;
            case 5:
                st->state = WIFI_TLS_CLOSED;
                return 0;
            default:
                return WIFI_TLS_UNSENT; // once
        }
    }
    module_steps++;
    if (!module_established) {
        st->state = WIFI_TLS_HANDSHAKING;
        if (module_steps == 1) {
            st->ct_out_len = 100; // ClientHello
        } else {
            module_ct_seen += st->ct_in_len;
            if (module_ct_seen >= 180) {
                module_established = true;
                st->state = WIFI_TLS_ESTABLISHED;
                st->ct_out_len = 50; // Finished
            }
        }
        return 0;
    }
    st->state = WIFI_TLS_ESTABLISHED;
    if (st->pt_in_len) {
        st->ct_out_len = st->pt_in_len + 22;
        server_echo_owed += st->pt_in_len;
    }
    // Each byte of the server's ciphertext is one byte of echo, in this world.
    uint16_t pt = st->ct_in_len;
    if (pt > st->pt_out_room) {
        pt = st->pt_out_room;
    }
    for (int i = 0; i < pt; i++) {
        st->pt_out[i] = pattern(echo_returned + i) ^ ((corrupt_echo && (echo_returned + i == 1000)) ? 1 : 0);
    }
    echo_returned += pt;
    st->pt_out_len = pt;
    return 0;
}

int wifi_tls_close(uint8_t session, int *esp_err)
{
    calls.push_back("tlsclose");
    *esp_err = 0;
    if (!module_open || (session != 1)) {
        calls.push_back("CLOSE OF A SESSION NOT OPEN");
    }
    if (fails(K_CLOSE)) {
        if (fail_variant == 0) {
            return WIFI_TLS_BUSY;
        }
        if (fail_variant == 1) {
            persistent = true;
            persistent_kind = K_CLOSE;
        }
        return WIFI_TLS_UNSENT;
    }
    module_open = false;
    return 0;
}

int wifi_tls_stats(uint8_t session, wifi_tls_stats_t *stats, int *esp_err)
{
    calls.push_back(session == WIFI_TLS_SESSION_GLOBAL ? "stats" : "sessionstats");
    *esp_err = 0;
    if (fails(K_STATS)) {
        return (fail_variant == 0) ? WIFI_TLS_BUSY : WIFI_TLS_UNSENT;
    }
    memset(stats, 0, sizeof(*stats));
    stats->heap_free = 100000;
    stats->tls_version = 0x0304;
    return 0;
}

static void reset_world(int at, int variant)
{
    fail_at = at;
    fail_variant = variant;
    persistent = false;
    persistent_kind = -1;
    event = 0;
    failed_kind = -1;
    calls.clear();
    now = 1000;
    sock_open = connecting = false;
    connect_polls = 0;
    module_open = module_established = false;
    module_steps = 0;
    module_ct_seen = 0;
    server_to_send = server_echo_owed = echo_owed_next = echo_returned = 0;
    corrupt_echo = false;
    surplus_echo = 0;
    allocated = NULL;
    frees = 0;
}

// The invariants every run must keep, whatever failed.
static std::string broken(const wifi_tls_spike_result_t &r, bool fatal)
{
    std::string why;
    int socket_closes = 0, opens_ok = r.session_opened ? 1 : 0, tls_closes = 0;
    size_t last_io = 0, first_cleanup = calls.size(), last_session_use = 0, first_tlsclose = calls.size();
    for (size_t i = 0; i < calls.size(); i++) {
        const std::string &c = calls[i];
        if (c.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0 && c.compare(0, 5, "FAULT") != 0) {
            why += c + "; ";
        }
        if (c == "closesocket") { socket_closes++; if (first_cleanup == calls.size()) first_cleanup = i; }
        if ((c == "send") || (c == "recv") || (c == "poll") || (c == "connect") || (c == "setsockopt")) last_io = i;
        if ((c == "step") || (c == "sessionstats")) last_session_use = i;
        if (c == "tlsclose") { tls_closes++; if (first_tlsclose == calls.size()) first_tlsclose = i; }
    }
    bool socket_made = r.socket_opened;
    if (socket_made != (socket_closes == 1)) why += "socket closed " + std::to_string(socket_closes) + " times; ";
    if (!socket_made && socket_closes) why += "closed a socket never made; ";
    if (last_io > first_cleanup) why += "socket used after close; ";
    if (opens_ok && !tls_closes) why += "session left open; ";
    if (!opens_ok && tls_closes) why += "closed a session never opened; ";
    if (tls_closes > 11) why += "close retried without bound; ";
    if (last_session_use > first_tlsclose) why += "session used after close; ";
    if (allocated && (frees != 1)) why += "buffer freed " + std::to_string(frees) + " times; ";
    size_t last = calls.size();
    while ((last > 0) && (calls[last - 1].compare(0, 5, "FAULT") == 0)) {
        last--;
    }
    if (!last || (calls[last - 1] != "stats")) why += "the last call is not the module's stats; ";
    if (!r.stage) why += "no stage; ";
    if (r.ok && fatal) why += "ok after a fatal fault; ";
    if (!r.ok && r.stage && !strcmp(r.stage, "done") && !r.close_result) why += "not ok but done; ";
    if (now > 1000 + 2 * 3000 + 5000) why += "ran past every deadline (" + std::to_string(now) + " ticks); ";
    return why;
}

// A failed STATS costs only its numbers, and an UNSENT that does not repeat is
// sent again; nothing else is survivable.
static bool fatal(int kind, int variant)
{
    bool transient_unsent = ((kind == K_OPEN) && (variant == 4)) || ((kind == K_STEP) && (variant == 6)) ||
                            ((kind == K_CLOSE) && (variant == 2)) || ((kind == K_STATS) && (variant == 1));
    return (kind >= 0) && (kind != K_STATS) && !transient_unsent;
}

int main(void)
{
    printf("The exits of the TLS spike\n");
    wifi_tls_spike_result_t r;
    const int echo = 3000;

    reset_world(-1, 0);
    wifi_tls_spike("10.0.0.2", 4433, "test.local", WIFI_TLS_FLAG_VERIFY | WIFI_TLS_FLAG_TEST_CA, echo, &r);
    int fallible = event;
    std::string why = broken(r, false);
    check(r.ok && r.echo_ok && (r.echo_received == echo) && (r.echo_sent == echo) && !strcmp(r.stage, "done") &&
          r.session_opened && (r.close_result == 0) && r.have_before && r.have_peak && r.have_after && why.empty(),
          "a clean run completes the handshake, echoes %d bytes and closes everything (%d steps, %d fallible calls) %s",
          echo, r.steps, fallible, why.c_str());

    std::map<std::string, int> stages;
    int runs = 0, bad = 0;
    for (int at = 0; at < fallible + 40; at++) {
        for (int v = 0; v < 6; v++) {
            reset_world(at, v);
            // Which kind the call at this index is decides how many variants it has;
            // that is only known once it has been reached.
            wifi_tls_spike("10.0.0.2", 4433, "test.local", WIFI_TLS_FLAG_VERIFY | WIFI_TLS_FLAG_TEST_CA, echo, &r);
            if (failed_kind < 0) {
                break; // past the last fallible call of this run
            }
            if (v >= variants[failed_kind]) {
                break;
            }
            runs++;
            std::string w = broken(r, fatal(failed_kind, v));
            if (!fatal(failed_kind, v) && ((failed_kind != K_STATS) || (v == 1)) && !r.ok) {
                w += "not ok after a fault it should survive; ";
            }
            char key[80];
            snprintf(key, sizeof(key), "%-10s v%d -> %s", kind_names[failed_kind], v, r.stage ? r.stage : "(none)");
            stages[key]++;
            if (!w.empty()) {
                if (bad++ < 10) {
                    printf("        fault at %d (%s v%d), stage %s: %s\n", at, kind_names[failed_kind], v, r.stage, w.c_str());
                }
            }
        }
    }
    check(bad == 0, "%d runs with one call failing, at every fallible call and in every way: invariants hold (%d broken)",
          runs, bad);
    printf("        where the runs ended (failed call, variant -> stage: runs):\n");
    for (std::map<std::string, int>::iterator it = stages.begin(); it != stages.end(); ++it) {
        printf("          %s: %d\n", it->first.c_str(), it->second);
    }

    reset_world(-1, 0);
    wifi_tls_spike("not an address", 4433, "", 0, 10, &r);
    std::string all;
    for (size_t i = 0; i < calls.size(); i++) {
        all += calls[i] + " ";
    }
    check(!r.ok && !strcmp(r.stage, "host") && !r.socket_opened && !r.session_opened && broken(r, true).empty() &&
          (all == "stats free stats "),
          "a host that is not an IPv4 address opens nothing (%s)", all.c_str());

    reset_world(-1, 0);
    corrupt_echo = true;
    wifi_tls_spike("10.0.0.2", 4433, "test.local", 0, echo, &r);
    check(!r.ok && !strcmp(r.stage, "echo_compare") && !r.echo_ok && broken(r, true).empty(),
          "one wrong byte of echo fails the run, which still closes everything");

    reset_world(-1, 0);
    surplus_echo = 5;
    wifi_tls_spike("10.0.0.2", 4433, "test.local", 0, echo, &r);
    check(!r.ok && !strcmp(r.stage, "echo_compare") && !r.echo_ok && broken(r, true).empty(),
          "more echo than was sent fails the run");

    reset_world(-1, 0);
    wifi_tls_spike("10.0.0.2", 4433, NULL, 0, 0, &r);
    check(r.ok && r.echo_ok && (r.echo_sent == 0) && broken(r, false).empty(), "a run without echo");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
