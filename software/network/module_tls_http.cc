#include "module_tls_http.h"
#include <stdlib.h>
#include <string.h>
#include <new>

// Limits taken from target 3 (network_target_tls.cc), which runs the same module calls.
#define RPC_STEP_MS        5000
#define RPC_OPEN_MS        5000
#define DNS_CONNECT_MS     10000
#define HANDSHAKE_MS       15000
#define SEND_MS            5000
#define NOTIFY_SEND_MS     100
#define SLICE_MS           100   // the longest a wait goes without looking at the token
#define UNSENT_DELAY_MS    50
#define AGAIN_DELAY_MS     5
#define WRITE_CHUNK        512   // plaintext per step, so that its record fits one step's ciphertext room
#define WRITE_STEPS        4
#define MAX_HOST           253   // WIFI_TLS_MAX_SNI

static bool reached(uint32_t now, uint32_t at) { return (int32_t)(now - at) >= 0; }

class ModuleTlsHttpProvider::Connection : public HttpConnection
{
    ModuleTlsHttpProvider& provider_;
    ModuleTlsPort& port_;
    OperationCancellation token_;
    uint32_t deadline_;          // the end of the whole request
    bool attempted_, closed_, opened_;
    bool have_slot_, live_;      // a slot is held; the module may hold a session in it
    uint8_t slot_;
    uint16_t tag_;
    int sock_;
    bool fin_, eof_, module_more_;
    uint16_t held_len_, rx_off_, rx_len_;
    uint8_t held_[WIFI_TLS_STEP_MAX_IN];
    uint8_t ct_[WIFI_TLS_STEP_MAX_OUT];
    uint8_t rx_[WIFI_TLS_STEP_MAX_OUT];   // plaintext the module handed out, not yet read

    // The predicate of every module call and wait: the token, and the one deadline.
    static bool stopped(void *context)
    {
        Connection *c = static_cast<Connection *>(context);
        return c->token_.cancelled() || reached(c->port_.now_ms(), c->deadline_);
    }
    wifi_tls_cancel_t cancel() { wifi_tls_cancel_t c = { stopped, this }; return c; }
    bool stop() { return stopped(this); }
    // The time left to the deadline, capped.
    uint32_t left(uint32_t cap)
    {
        int32_t n = (int32_t)(deadline_ - port_.now_ms());
        return n <= 0 ? 0 : (uint32_t)n < cap ? (uint32_t)n : cap;
    }
    int fail()
    {
        close_session();
        return -1;
    }
    // Every ciphertext goes out, or the exchange is over.
    bool send_out(const uint8_t *data, int length)
    {
        if (length <= 0) return true;
        wifi_tls_cancel_t c = cancel();
        return port_.tcp_send(sock_, data, length, left(SEND_MS), &c) == 0;
    }
    int run_step(wifi_tls_step_t *st)
    {
        wifi_tls_cancel_t c = cancel();
        int result = WIFI_TLS_BUSY;
        for (int i = 0; ; i++) {
            uint32_t budget = left(RPC_STEP_MS);
            if (!budget) return WIFI_TLS_BUSY;
            result = wifi_tls_step(slot_, tag_, st, budget, &c);
            if (result != WIFI_TLS_UNSENT || stop()) break; // until the request's deadline
            port_.sleep_ms(UNSENT_DELAY_MS);
        }
        return result;
    }
    // Waits at most a slice for ciphertext. >0 taken into held_; 0 none yet; -1 the exchange is over.
    int fetch()
    {
        uint32_t budget = left(SLICE_MS);
        if (!budget) return -1;
        wifi_tls_cancel_t c = cancel();
        int n = port_.tcp_recv(sock_, held_, sizeof(held_), budget, &c);
        if (n > 0) { held_len_ = (uint16_t)n; return n; }
        if (n == 0) return 0;
        if (n == -1) { fin_ = true; return 0; }
        return -1;
    }
    void prepare(wifi_tls_step_t *st)
    {
        memset(st, 0, sizeof(*st));
        st->ct_out = ct_;
        st->ct_out_room = sizeof(ct_);
    }

    // A CLOSE sent again while another caller holds the module thread, until end.
    int close_retried(uint8_t slot, uint16_t tag, uint32_t end, uint16_t *notify, int *esp_err)
    {
        int result;
        while (true) {
            int32_t room = (int32_t)(end - port_.now_ms());
            result = wifi_tls_close(slot, tag, ct_, sizeof(ct_), notify, esp_err, room > 0 ? (uint32_t)room : 1, NULL);
            if (result != WIFI_TLS_UNSENT || (int32_t)(end - port_.now_ms()) <= UNSENT_DELAY_MS) break;
            port_.sleep_ms(UNSENT_DELAY_MS);
        }
        return result;
    }
    // OPEN, DNS and connect first (a dead network costs the module nothing), then the handshake.
    int establish(const char *host, uint16_t port)
    {
        port_.reclaim_withheld(left(provider_.cleanup_ms_));
        if (!port_.take_slot(&slot_, &tag_)) return -1;
        have_slot_ = true;
        wifi_tls_cancel_t c = cancel();
        if (port_.tcp_connect(host, port, left(DNS_CONNECT_MS), &c, &sock_) != 0) { sock_ = -1; return -1; }
        wifi_tls_open_t open;
        memset(&open, 0, sizeof(open));
        open.trust = WIFI_TLS_TRUST_BUNDLE;
        open.slot = slot_;
        open.tag = tag_;
        uint32_t now = port_.utc_now();
        open.time_source = now ? WIFI_TLS_TIME_NIOS : WIFI_TLS_TIME_NONE;
        open.unix_time = now;
        open.sni = host;
        open.sni_len = (uint8_t)strlen(host);
        int esp_err = 0, result = WIFI_TLS_BUSY;
        uint8_t reason = 0;
        for (int i = 0; ; i++) {
            uint32_t budget = left(RPC_OPEN_MS);
            if (!budget) break;
            result = wifi_tls_open(&open, budget, &c, &esp_err, &reason);
            if (result != WIFI_TLS_UNSENT || stop()) break; // until the request's deadline
            port_.sleep_ms(UNSENT_DELAY_MS);
        }
        if (result == WIFI_TLS_NO_MODULE || result == WIFI_TLS_REFUSED) return -1;
        // No answer, or one that makes no sense: the module may hold the session all the same.
        live_ = true;
        if (result != 0) return -1;
        return handshake();
    }
    int handshake()
    {
        uint32_t now = port_.now_ms();
        uint32_t hs_end = now + HANDSHAKE_MS;
        bool more = true; // the first step, with no input, makes the ClientHello
        held_len_ = 0;
        while (true) {
            if (stop() || reached(port_.now_ms(), hs_end)) return -1;
            if (held_len_ == 0 && !more) {
                if (fetch() < 0 || fin_) return -1; // a peer that ends the stream mid-handshake has failed it
                if (held_len_ == 0) continue;
            }
            wifi_tls_step_t st;
            prepare(&st);
            st.ct_in = held_;
            st.ct_in_len = held_len_;
            st.pt_out = rx_;
            st.pt_out_room = sizeof(rx_);
            int result = run_step(&st);
            if (result != 0 && result != WIFI_TLS_AGAIN) {
                if (result == WIFI_TLS_REFUSED && st.esp_err == WIFI_TLS_ESP_NOT_FOUND) live_ = false;
                return -1;
            }
            if (result == 0) held_len_ = 0;
            if (st.state == WIFI_TLS_FAILED || st.state == WIFI_TLS_CLOSED) live_ = false;
            // Every ciphertext goes out before the next step, a failure's alert too.
            bool sent = send_out(ct_, st.ct_out_len);
            if (st.state == WIFI_TLS_FAILED || st.state == WIFI_TLS_CLOSED || !sent) return -1;
            if (st.state == WIFI_TLS_ESTABLISHED) {
                rx_len_ = st.pt_out_len;
                rx_off_ = 0;
                module_more_ = true;
                return 0;
            }
            more = st.ct_out_len != 0 || result == WIFI_TLS_AGAIN;
        }
    }

public:
    // Match the firmware's wrapped malloc/free pair, as the owner provider does.
    static void *operator new(size_t bytes) noexcept { return malloc(bytes); }
    static void operator delete(void *memory) noexcept { free(memory); }
    Connection(ModuleTlsHttpProvider& p, const OperationCancellation& token) :
        provider_(p), port_(p.port_), token_(token), deadline_(0), attempted_(false), closed_(false), opened_(false),
        have_slot_(false), live_(false), slot_(0), tag_(0), sock_(-1), fin_(false), eof_(false), module_more_(false),
        held_len_(0), rx_off_(0), rx_len_(0) {}
    ~Connection() override
    {
        close_session();
        provider_.occupied_ = false;
    }
    // A host with whitespace or control bytes, an IPv6 literal, or an IPv4 one by lwIP's own ip4addr_aton (through
    // the port, as target 3 does): bundle trust checks a name, so a literal is refused and no address is sent as SNI.
    bool is_literal(const char *host, size_t length)
    {
        for (size_t i = 0; i < length; i++) {
            uint8_t c = (uint8_t)host[i];
            if (c <= ' ' || c == 0x7F || c == ':') return true;   // whitespace, control, or an IPv6 literal
        }
        return port_.is_ipv4_literal(host);
    }
    int open(const char *host, uint16_t port) override
    {
        if (closed_ || attempted_) return -1;
        attempted_ = true;
        deadline_ = port_.now_ms() + provider_.exchange_ms_;
        if (!host || !port) return -1;
        size_t length = strnlen(host, MAX_HOST + 1);
        if (!length || length > MAX_HOST || is_literal(host, length)) return -1;
        if (stop() || !port_.module_ready()) return fail();
        if (establish(host, port) != 0) return fail();
        opened_ = true;
        return 0;
    }
    int read(void *buffer, int count) override
    {
        if (!opened_ || closed_ || !buffer || count <= 0) return -1;
        uint8_t *out = static_cast<uint8_t *>(buffer);
        while (true) {
            // Whatever is buffered, and whatever a step just produced, is dropped once the exchange is over: the
            // token and the deadline are looked at before every result is handed out, an end of stream included.
            if (stop()) return fail();
            if (rx_off_ < rx_len_) {
                int n = rx_len_ - rx_off_;
                if (n > count) n = count;
                memcpy(out, rx_ + rx_off_, n);
                rx_off_ += n;
                return n;
            }
            if (eof_) return 0;
            if (held_len_ == 0 && !module_more_) {
                if (fetch() < 0) return fail();
                if (fin_) module_more_ = true; // one last drain step, then the end
                if (held_len_ == 0 && !module_more_) continue;
            }
            wifi_tls_step_t st;
            prepare(&st);
            st.ct_in = held_;
            st.ct_in_len = held_len_;
            st.pt_out = rx_;
            st.pt_out_room = sizeof(rx_);
            int result = run_step(&st);
            if (result != 0 && result != WIFI_TLS_AGAIN) {
                if (result == WIFI_TLS_REFUSED && st.esp_err == WIFI_TLS_ESP_NOT_FOUND) live_ = false;
                return fail();
            }
            if (result == 0) held_len_ = 0;
            if (st.state == WIFI_TLS_FAILED) live_ = false;
            if (!send_out(ct_, st.ct_out_len) || st.state == WIFI_TLS_FAILED) return fail();
            rx_off_ = 0;
            rx_len_ = st.pt_out_len;
            if (st.state == WIFI_TLS_CLOSED) {
                live_ = false;     // the peer's close_notify ended the session on the module
                eof_ = true;       // what it handed out is read first
                continue;
            }
            if (st.state != WIFI_TLS_ESTABLISHED) return fail();
            module_more_ = st.pt_out_len || st.ct_out_len || result == WIFI_TLS_AGAIN;
            if (!module_more_ && fin_ && held_len_ == 0 && !rx_len_) {
                return fail();     // a TCP end without close_notify is a truncation, never a clean end (target 3: status 05)
            }
        }
    }
    int write(const void *buffer, int count) override
    {
        if (!opened_ || closed_ || !buffer || count <= 0) return -1;
        int n = count > WRITE_CHUNK ? WRITE_CHUNK : count;
        bool taken = false;
        for (int steps = 0; steps < WRITE_STEPS + 40; steps++) {
            if (stop()) return fail();
            wifi_tls_step_t st;
            prepare(&st);
            st.flags = WIFI_TLS_STEP_NO_READ;
            st.pt_in = taken ? NULL : static_cast<const uint8_t *>(buffer);
            st.pt_in_len = taken ? 0 : n;
            st.pt_out = rx_ + rx_len_;      // refused by NO_READ; never handed out
            st.pt_out_room = 0;
            int result = run_step(&st);
            if (result != 0 && result != WIFI_TLS_AGAIN) {
                if (result == WIFI_TLS_REFUSED && st.esp_err == WIFI_TLS_ESP_NOT_FOUND) live_ = false;
                return fail();
            }
            if (st.state == WIFI_TLS_FAILED || st.state == WIFI_TLS_CLOSED) live_ = false;
            if (!send_out(ct_, st.ct_out_len) || st.state != WIFI_TLS_ESTABLISHED) return fail();
            if (result == 0) taken = true;
            if (taken && st.ct_out_len == 0) return stop() ? fail() : n;
            if (result == WIFI_TLS_AGAIN) port_.sleep_ms(AGAIN_DELAY_MS);
        }
        return fail();
    }
    // Safe after a failed open, and at any later point, once. Cleanup does not stop for the
    // token: an aborted exchange still tells the module to free its session.
    void close_session() override
    {
        if (closed_) return;
        closed_ = true;
        uint32_t start = port_.now_ms();
        bool withhold = false;
        if (live_) {
            uint16_t notify = 0;
            int esp_err = 0;
            // One budget for all of the cleanup: the CLOSE (sent again while another caller holds the module
            // thread) and the close_notify come first, and the socket's disposal keeps the port's worst case.
            uint32_t body_end = start + provider_.cleanup_ms_ - port_.tcp_close_max_ms();
            uint32_t notify_ms = (provider_.cleanup_ms_ - port_.tcp_close_max_ms()) / 2;
            if (notify_ms > NOTIFY_SEND_MS) notify_ms = NOTIFY_SEND_MS;
            int result = close_retried(slot_, tag_, body_end - notify_ms, &notify, &esp_err);
            int32_t room = (int32_t)(body_end - port_.now_ms());
            if (result == 0 && notify && sock_ >= 0 && room > 0) {
                port_.tcp_send(sock_, ct_, notify, (uint32_t)room < NOTIFY_SEND_MS ? (uint32_t)room : NOTIFY_SEND_MS, NULL);
            }
            // No acknowledgement: the module may still hold the session, and the slot may not be lent again.
            withhold = !wifi_tls_close_confirmed(result, esp_err);
            live_ = false;
        }
        if (sock_ >= 0) {
            port_.tcp_close(sock_);
            sock_ = -1;
        }
        if (have_slot_) {
            if (withhold) port_.withhold_slot(slot_, tag_);
            else port_.give_slot(slot_);
            have_slot_ = false;
        }
    }
};

ModuleTlsHttpProvider::ModuleTlsHttpProvider(ModuleTlsPort& port, uint32_t exchange_ms, uint32_t cleanup_ms) :
    port_(port), exchange_ms_(exchange_ms), cleanup_ms_(cleanup_ms), occupied_(false) {}

bool ModuleTlsHttpProvider::available() const
{
    return exchange_ms_ && exchange_ms_ <= INT32_MAX && cleanup_ms_ && cleanup_ms_ <= INT32_MAX &&
           cleanup_ms_ > port_.tcp_close_max_ms() && port_.module_ready();
}

HttpConnection *ModuleTlsHttpProvider::create_connection(const OperationCancellation& token)
{
    if (!available() || token.cancelled()) return 0;
    // Only the UCI Server task creates a connection and only a connection's owner clears this, a byte store;
    // the core has no atomic read-modify-write.
    if (occupied_) return 0;
    occupied_ = true;
    Connection *connection = new Connection(*this, token);
    if (!connection) occupied_ = false;
    return connection;
}
