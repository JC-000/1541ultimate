// Target 6 over the WiFi module's TLS sessions: a UCI HTTP exchange with an
// https:// URL, through the real HttpTarget and the real ModuleTlsHttpProvider,
// against a fake module (wifi_tls_open/step/close) and a fake TCP peer. The
// fake speaks a small record format in place of TLS; what the adapter owes is
// the pump around it (DNS/connect, open, step until established, write, read,
// close), the one deadline, the cancellation token, and never plaintext.
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <deque>
#include "http_target.h"
#include "http_target_test_support.h"
#include "module_tls_http.h"
#include "../../test/wifi_tls/netstub/lwip/dns.h" // ip4addr_aton: a copy of lwIP's, as target 3's host tests use

static int checks, failures;
static void expect(bool ok, const char *label)
{
    ++checks;
    if (!ok) { ++failures; printf("FAIL %s\n", label); }
}

// ---- what a scenario does -------------------------------------------------
struct Scenario {
    std::string cert_name = "secure.test"; // what the server's certificate names
    std::string body = "{\"answer\":42}";
    bool silent = false;                   // the server never answers the request
    bool notify = true;                    // close_notify after the response, else TCP end
    bool no_time = false;                  // the clock is not trustworthy
    bool slot_free = true;
    bool connect_fails = false;
    int open_unsent = 0, step_unsent = 0, close_unsent = 0; // answer UNSENT this many times first: another caller holds the thread
    bool open_unanswered = false;          // the module starts the session but its OPEN answer is lost
    bool no_length = false;                // no Content-Length: the body runs to the end of the connection
    int cut = 0;                           // bytes of the body the server never sends
    int fragment = 5;                      // the most bytes one recv hands over
    CancellationSource *cancel_on_request = NULL;
};
static Scenario sc;

static uint32_t fake_now;
static int connects, tcp_closes, tcp_open, slots_taken, slots_given, module_opens, module_closes;
static int module_steps, notifies_seen, last_trust, last_time_source;
static std::string last_sni, request_seen, tcp_host;
static uint16_t tcp_port_seen;
static bool plaintext_on_wire;
static const uint8_t KEY = 0x5A;

static void put_record(std::string& out, char type, const std::string& payload, bool scramble)
{
    out += type;
    out += char(payload.size() & 0xFF);
    out += char(payload.size() >> 8);
    for (char c : payload) out += scramble ? char(uint8_t(c) ^ KEY) : c;
}
// Takes whole records off the front of buf. type, payload (unscrambled for D).
static bool take_record(std::string& buf, char *type, std::string *payload)
{
    if (buf.size() < 3) return false;
    size_t n = uint8_t(buf[1]) | (uint8_t(buf[2]) << 8);
    if (buf.size() < 3 + n) return false;
    *type = buf[0];
    payload->assign(buf, 3, n);
    if (*type == 'D') for (char& c : *payload) c = char(uint8_t(c) ^ KEY);
    buf.erase(0, 3 + n);
    return true;
}

// ---- the fake TCP peer ----------------------------------------------------
static std::string server_in, server_out, http_request;
static bool server_fin;
static void server_feed(const uint8_t *data, int length)
{
    if (length < 1 || (data[0] != 'H' && data[0] != 'D' && data[0] != 'C')) plaintext_on_wire = true;
    server_in.append((const char *)data, length);
    char type; std::string payload;
    while (take_record(server_in, &type, &payload)) {
        if (type == 'H' && payload.compare(0, 2, "CH") == 0) put_record(server_out, 'H', "SH:" + sc.cert_name, false);
        if (type == 'C') ++notifies_seen;
        if (type == 'D') {
            http_request += payload;
            if (http_request.find("\r\n\r\n") != std::string::npos && !sc.silent && server_out.find('D') == std::string::npos) {
                request_seen = http_request;
                if (sc.cancel_on_request) sc.cancel_on_request->signal();
                std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                                       (sc.no_length ? std::string() : "Content-Length: " + std::to_string(sc.body.size()) + "\r\n") +
                                       "\r\n" + sc.body.substr(0, sc.body.size() - sc.cut);
                for (size_t at = 0; at < response.size(); at += 40) put_record(server_out, 'D', response.substr(at, 40), true);
                if (sc.notify) put_record(server_out, 'C', "", false); else server_fin = true;
            }
        }
    }
}

struct FakePort : ModuleTlsPort {
    bool module_ready() override { return true; }
    uint32_t now_ms() override { return fake_now; }
    void sleep_ms(uint32_t ms) override { fake_now += ms; }
    uint32_t utc_now() override { return sc.no_time ? 0 : 1800000000u; }
    bool take_slot(uint8_t *slot, uint16_t *tag) override {
        if (!sc.slot_free) return false;
        ++slots_taken; *slot = 1; *tag = 77; return true;
    }
    void give_slot(uint8_t) override { ++slots_given; }
    int tcp_connect(const char *host, uint16_t port, uint32_t, const wifi_tls_cancel_t *, int *handle) override {
        if (sc.connect_fails) return 111;
        ++connects; ++tcp_open; tcp_host = host; tcp_port_seen = port; *handle = 9; return 0;
    }
    int tcp_send(int, const uint8_t *data, int length, uint32_t, const wifi_tls_cancel_t *) override {
        server_feed(data, length); return 0;
    }
    int tcp_recv(int, uint8_t *buffer, int room, uint32_t budget, const wifi_tls_cancel_t *cancel) override {
        if (cancel && cancel->cancelled && cancel->cancelled(cancel->context)) return 0;
        if (server_out.empty()) {
            fake_now += budget;
            return server_fin ? -1 : 0;
        }
        int n = (int)server_out.size();
        if (n > room) n = room;
        if (n > sc.fragment) n = sc.fragment;
        memcpy(buffer, server_out.data(), n);
        server_out.erase(0, n);
        return n;
    }
    void tcp_close(int) override { ++tcp_closes; --tcp_open; }
    bool is_ipv4_literal(const char *host) override { ip4_addr_t a; return ip4addr_aton(host, &a) != 0; }
};

// ---- the fake module ------------------------------------------------------
struct Session {
    bool live; uint16_t tag; uint8_t state; bool sent_hello;
    std::string in, plain_ready;
} sessions[2];

int wifi_tls_open(const wifi_tls_open_t *open, uint32_t, const wifi_tls_cancel_t *, int *esp_err, uint8_t *reason)
{
    *esp_err = 0; *reason = 0;
    if (sc.open_unsent > 0) { --sc.open_unsent; return WIFI_TLS_UNSENT; }
    ++module_opens;
    last_trust = open->trust; last_time_source = open->time_source;
    last_sni.assign(open->sni ? open->sni : "", open->sni ? open->sni_len : 0);
    if (open->trust != WIFI_TLS_TRUST_PIN && open->time_source == WIFI_TLS_TIME_NONE) {
        *reason = WIFI_TLS_REASON_NO_TIME; return WIFI_TLS_REFUSED;
    }
    Session& s = sessions[open->slot];
    s = Session(); s.live = true; s.tag = open->tag; s.state = WIFI_TLS_HANDSHAKING;
    return sc.open_unanswered ? WIFI_TLS_BUSY : 0;
}
int wifi_tls_step(uint8_t slot, uint16_t tag, wifi_tls_step_t *st, uint32_t, const wifi_tls_cancel_t *cancel)
{
    if (sc.step_unsent > 0 && true) { --sc.step_unsent; return WIFI_TLS_UNSENT; }
    ++module_steps;
    if (cancel && cancel->cancelled && cancel->cancelled(cancel->context)) return WIFI_TLS_BUSY;
    Session& s = sessions[slot];
    st->ct_out_len = st->pt_out_len = 0; st->esp_err = 0; st->alert_in = WIFI_TLS_ALERT_NONE; st->alert_out = WIFI_TLS_ALERT_NONE;
    st->fail_reason = 0; st->verify_flags = 0;
    if (!s.live || s.tag != tag) { st->esp_err = WIFI_TLS_ESP_NOT_FOUND; return WIFI_TLS_REFUSED; }
    s.in.append((const char *)st->ct_in, st->ct_in_len);
    std::string out;
    if (s.state == WIFI_TLS_HANDSHAKING && !s.sent_hello) {
        s.sent_hello = true;
        put_record(out, 'H', "CH" + last_sni, false);
    }
    char type; std::string payload;
    while (s.state != WIFI_TLS_FAILED && s.state != WIFI_TLS_CLOSED && take_record(s.in, &type, &payload)) {
        if (s.state == WIFI_TLS_HANDSHAKING && type == 'H') {
            if (payload != "SH:" + last_sni) {
                s.state = WIFI_TLS_FAILED; st->fail_reason = WIFI_TLS_FAIL_CERT_VERIFY; st->verify_flags = 0x04;
                s.live = false;
            } else {
                s.state = WIFI_TLS_ESTABLISHED;
                put_record(out, 'H', "FIN", false);
            }
        } else if (s.state == WIFI_TLS_ESTABLISHED && type == 'D') {
            s.plain_ready += payload;
        } else if (type == 'C') {
            s.state = WIFI_TLS_CLOSED; s.live = false;
        }
    }
    if (s.state == WIFI_TLS_ESTABLISHED && st->pt_in_len) put_record(out, 'D', std::string((const char *)st->pt_in, st->pt_in_len), true);
    if (!(st->flags & WIFI_TLS_STEP_NO_READ) && !s.plain_ready.empty()) {
        size_t n = s.plain_ready.size() < st->pt_out_room ? s.plain_ready.size() : st->pt_out_room;
        memcpy(st->pt_out, s.plain_ready.data(), n); st->pt_out_len = (uint16_t)n; s.plain_ready.erase(0, n);
    }
    if (out.size() > st->ct_out_room) { out.resize(st->ct_out_room); } // never happens for these sizes
    memcpy(st->ct_out, out.data(), out.size()); st->ct_out_len = (uint16_t)out.size();
    st->state = s.state;
    return 0;
}
int wifi_tls_close(uint8_t slot, uint16_t tag, uint8_t *ct_out, uint16_t room, uint16_t *ct_out_len, int *esp_err,
                   uint32_t, const wifi_tls_cancel_t *)
{
    if (sc.close_unsent > 0) { --sc.close_unsent; return WIFI_TLS_UNSENT; }
    ++module_closes;
    *esp_err = 0; *ct_out_len = 0;
    Session& s = sessions[slot];
    if (!s.live || s.tag != tag) { *esp_err = WIFI_TLS_ESP_NOT_FOUND; return WIFI_TLS_REFUSED; }
    std::string out; put_record(out, 'C', "", false);
    if (out.size() <= room) { memcpy(ct_out, out.data(), out.size()); *ct_out_len = (uint16_t)out.size(); }
    s.live = false;
    return 0;
}

// ---- the target -----------------------------------------------------------
struct Reply { std::string data, status; };
static Reply command(HttpTarget& target, std::vector<uint8_t> bytes)
{
    Message cmd = {int(bytes.size()), true, bytes.data()}, *data, *status;
    run_target_command(target, &cmd, &data, &status);
    target.prepare_reply(&data, &status);
    Reply r = {std::string(reinterpret_cast<char *>(data->message), data->length),
               std::string(reinterpret_cast<char *>(status->message), status->length)};
    target.finish_reply(true);
    return r;
}
static uint8_t header(HttpTarget& target, const std::string& url)
{
    std::vector<uint8_t> bytes = {6, HTTP_CMD_HEADER_CREATE, 1};
    bytes.insert(bytes.end(), url.begin(), url.end());
    Reply r = command(target, bytes);
    return r.data.empty() ? 0 : uint8_t(r.data[0]);
}
static Reply get(HttpTarget& target, const std::string& url)
{
    uint8_t hdr = header(target, url);
    return command(target, {6, HTTP_CMD_DO_EXCHANGE_RAW, hdr, 255});
}
static void reset(const Scenario& s)
{
    sc = s;
    fake_now = 1000;
    connects = tcp_closes = tcp_open = slots_taken = slots_given = module_opens = module_closes = 0;
    module_steps = notifies_seen = last_trust = last_time_source = 0;
    last_sni.clear(); request_seen.clear(); tcp_host.clear(); tcp_port_seen = 0;
    plaintext_on_wire = false; server_in.clear(); server_out.clear(); http_request.clear(); server_fin = false;
    for (Session& session : sessions) session = Session();
}
static void balanced(const char *label)
{
    expect(slots_taken == slots_given && tcp_open == 0 && !sessions[0].live && !sessions[1].live && !plaintext_on_wire, label);
}

extern "C" void outbyte(int byte) { fputc(byte, stdout); }
static const char *URL = "https://secure.test/probe";

int main()
{
    static FakePort port;
    {   // The GET: the module's bundle, the URL's host as SNI, the body back, everything released.
        reset(Scenario());
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status.compare(0, 15, "HTTP/1.1 200 OK") == 0 && r.data == "{\"answer\":42}", "https GET over the module returns the body");
        expect(request_seen.compare(0, 14, "GET /probe HTT") == 0 && request_seen.find("Host: secure.test") != std::string::npos,
               "the server received the request through the module");
        expect(last_trust == WIFI_TLS_TRUST_BUNDLE && last_sni == "secure.test", "bundle trust, SNI is the host");
        expect(last_time_source == WIFI_TLS_TIME_NIOS, "the clock went to the module");
        expect(tcp_host == "secure.test" && tcp_port_seen == 443, "TCP to the URL's host and default port");
        balanced("all resources released after a GET");
        expect(slots_taken == 1 && module_opens == 1 && notifies_seen == 1, "one slot, one session, close_notify sent");
    }
    {   // A TCP end without close_notify still ends the body at its length.
        Scenario s; s.notify = false; s.body = std::string(300, 'x'); s.fragment = 1000;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.data == s.body, "a response with a TCP end instead of close_notify");
        balanced("released after a TCP end");
    }
    {   // No Content-Length, the body cut short, TCP end without close_notify: that is a truncation, not a 200.
        Scenario s; s.notify = false; s.no_length = true; s.cut = 5; s.body = std::string(300, 'x'); s.fragment = 1000;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status.compare(0, 15, "HTTP/1.1 200 OK") != 0, "a body cut by a TCP end without close_notify is not a 200");
        balanced("released after a truncated body");
    }
    {   // A certificate for another name: the module fails the handshake; no body, nothing leaked.
        Scenario s; s.cert_name = "other.test";
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && r.data.empty() && request_seen.empty(), "name mismatch: no request is sent");
        balanced("released after a failed handshake");
    }
    {   // No trustworthy clock: the module refuses the OPEN; no TLS means no request.
        Scenario s; s.no_time = true;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && r.data.empty() && !request_seen.size(), "no trusted time: refused");
        balanced("released after a refused OPEN");
    }
    {   // No free slot, and no route: refused before anything opens.
        Scenario s; s.slot_free = false;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && !connects && !module_opens, "no slot: nothing opened");
        s.slot_free = true; s.connect_fails = true;
        reset(s);
        r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && !module_opens, "connect failure: no OPEN, no plaintext");
        balanced("released after a connect failure");
    }
    {   // One deadline for the whole request: a silent server ends it at exchange_ms, with cleanup.
        Scenario s; s.silent = true;
        reset(s);
        ModuleTlsHttpProvider provider(port, 8000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && r.data.empty(), "silent server: the exchange fails");
        expect(fake_now >= 1000 + 8000 && fake_now <= 1000 + 8000 + 600, "the failure comes at the request deadline");
        balanced("released after the deadline");
    }
    for (int phase = 0; phase < 2; ++phase) {   // The command's cancellation token, before and during the exchange.
        CancellationSource events;
        Scenario s; s.cancel_on_request = phase ? &events : NULL;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        uint8_t hdr = header(target, URL);
        target.begin_command(events.token());
        if (!phase) events.signal();
        Reply r = command(target, {6, HTTP_CMD_DO_EXCHANGE_RAW, hdr, 255});
        expect(r.status == "503 SERVICE UNAVAILABLE" && r.data.empty(), "cancelled exchange publishes nothing");
        expect(phase || (!connects && !module_opens), "cancelled before the start opens nothing");
        balanced("released after cancellation");
        reset(Scenario());
        target.begin_command(events.token());
        expect(get(target, URL).data == "{\"answer\":42}", "a fresh command works after a cancelled one");
    }
    {   // A literal address names no certificate: bundle trust refuses it, and no address is ever sent as SNI.
        const char *literals[] = { "https://192.0.2.1/probe", "https://[2001:db8::1]/probe", "https://[::1]:8443/probe", "https://0x7f.1/probe" };
        for (const char *u : literals) {
            reset(Scenario());
            ModuleTlsHttpProvider provider(port, 20000, 500);
            HttpTarget target(7, &provider);
            Reply r = get(target, u);
            // (the URL parser itself answers 500 to a bracketed IPv6 host; either way nothing opens)
            expect(r.data.empty() && r.status.compare(0, 3, "200") != 0 && !slots_taken && !connects && !module_opens && last_sni.empty(), u);
            balanced("nothing held for a literal address");
        }
        reset(Scenario());
        ModuleTlsHttpProvider provider(port, 20000, 500);
        const char *hosts[] = { "::1", "2001:db8::1", "10.0.0.1", "127.1", "0x7f.0.0.1", "2130706433",
                                "1.2.3.4\v", "1.2.3.4\f", "1.2.3.4 ", "1.2.3.4\t", "secure.test\v", "secure .test", "secure\x01.test", "secure.test\x7f" };
        for (const char *h : hosts) {
            HttpConnection *c = provider.create_connection(OperationCancellation());
            expect(c && c->open(h, 443) != 0 && !connects && !module_opens && !slots_taken, h);
            delete c;
        }
        {   // a name that only looks numeric is still a name
            Scenario n; n.cert_name = "1.example.com";
            reset(n);
            HttpConnection *c = provider.create_connection(OperationCancellation());
            expect(c && c->open("1.example.com", 443) == 0 && last_sni == "1.example.com", "1.example.com is a name");
            delete c;
        }
    }
    {   // Target 3 holds the module thread: UNSENT is sent again until the request's deadline (OPEN, STEP) or the cleanup budget (CLOSE).
        Scenario s; s.open_unsent = 100; s.step_unsent = 100; s.close_unsent = 15;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 1000);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status.compare(0, 15, "HTTP/1.1 200 OK") == 0 && r.data == "{\"answer\":42}", "UNSENT 100 times on OPEN and on STEP: the request still succeeds");
        expect(module_closes == 1 && !sessions[0].live && !sessions[1].live && notifies_seen == 1, "UNSENT on the cleanup CLOSE: sent again within its budget");
        balanced("released after UNSENT everywhere");
    }
    {   // ... but not past the deadline.
        Scenario s; s.open_unsent = 100000;
        reset(s);
        ModuleTlsHttpProvider provider(port, 8000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && fake_now <= 1000 + 8000 + 600, "UNSENT without end: the request fails at its deadline");
        balanced("released after an OPEN that is never sent");
    }
    {   // M5: an OPEN nobody answers may still have started the session: the CLOSE goes out all the same.
        Scenario s; s.open_unanswered = true;
        reset(s);
        ModuleTlsHttpProvider provider(port, 20000, 500);
        HttpTarget target(7, &provider);
        Reply r = get(target, URL);
        expect(r.status == "503 SERVICE UNAVAILABLE" && request_seen.empty(), "an unanswered OPEN fails the request");
        expect(module_closes == 1 && !sessions[1].live && !sessions[0].live, "an unanswered OPEN: a CLOSE frees the module's session");
        balanced("released after an unanswered OPEN");
    }
    {   // M3, below HttpTarget: the connection itself stops for the token, at open, during the handshake and mid-read.
        const char *req = "GET /probe HTTP/1.1\r\nHost: secure.test\r\n\r\n";
        char buf[64];
        {   CancellationSource events; reset(Scenario());
            ModuleTlsHttpProvider provider(port, 20000, 500);
            OperationCancellation token = events.token();
            events.signal();
            HttpConnection *c = provider.create_connection(token);
            expect(!c, "a connection is not made for a cancelled token");
            if (c) delete c;
            balanced("nothing held for a cancelled token");
        }
        {   CancellationSource events; reset(Scenario());
            ModuleTlsHttpProvider provider(port, 20000, 500);
            HttpConnection *c = provider.create_connection(events.token());
            events.signal();     // after the connection exists, before open
            expect(c && c->open("secure.test", 443) != 0 && !connects && !module_opens, "open for a token cancelled before it: refused, nothing opened");
            delete c;
            balanced("released after a cancelled open");
        }
        {   CancellationSource events; reset(Scenario());
            ModuleTlsHttpProvider provider(port, 20000, 500);
            HttpConnection *c = provider.create_connection(events.token());
            expect(c && c->open("secure.test", 443) == 0, "uncancelled: open works");
            events.signal();     // established, then cancelled
            expect(c->write(req, (int)strlen(req)) < 0 && request_seen.empty(), "write after cancellation fails, nothing sent");
            delete c;
            balanced("released after a cancelled write");
        }
        {   CancellationSource events; Scenario s; s.cancel_on_request = &events;
            reset(s);
            ModuleTlsHttpProvider provider(port, 20000, 500);
            HttpConnection *c = provider.create_connection(events.token());
            expect(c && c->open("secure.test", 443) == 0, "opened; the token is cancelled as the request reaches the server");
            c->write(req, (int)strlen(req));
            expect(c->read(buf, sizeof(buf)) < 0, "read after cancellation fails");
            delete c;
            balanced("released after a cancelled read");
        }
    }
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
