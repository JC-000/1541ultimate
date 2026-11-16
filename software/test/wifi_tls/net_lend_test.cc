/* Host test for the slots network_target_tls.cc lends to target 6 (tls_lend_slot / tls_return_slot): a lent slot
 * is never given to an OPEN_TLS, an OPEN_TLS never loses a slot it holds, and an OPEN that finds no slot left says 91.
 * Same world as net_tls_test.cc; a separate binary so that one's counts stay what they are. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "net_world.h"
#define class struct // execute() and close_sockets_after_reset() are private
#include "network_target.h"
#undef class
#include "check.h"

int failures;
int checks;

void check(bool condition, const char *what, ...)
{
    char line[400];
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

extern NetworkTarget net;

struct Res {
    bytes data;
    std::string status;
};

// One command as the C64 sends it, and every block of its reply as it reads them.
// The longest status any command of the run answered (the cap is 40 bytes).
static std::string longest_status;

// A C64 reset: the UCI Server task notes it, and the worker closes the sockets and the TLS sessions.
static void reset_c64(void)
{
    net.c64_reset();
    net.close_sockets_after_reset();
}

static Res run(const bytes &command)
{
    static uint8_t buf[1024];
    memcpy(buf, command.data(), command.size());
    Message m = { (int)command.size(), true, buf };
    Message *reply, *status;
    // The UCI Server task answers a socket-free command itself; any other runs on the worker, which is
    // not started here: execute() is called as the worker calls it, between its own housekeeping.
    if (net.is_quick(&m)) {
        net.parse_command(&m, &reply, &status);
    } else {
        static volatile bool not_cancelled;
        not_cancelled = false;
        net.close_sockets_after_reset();
        net.cancel = &not_cancelled;
        net.opened_socket = -1;
        net.execute(&m, &reply, &status);
        net.cancel = NULL;
        net.close_sockets_after_reset();
    }
    Res r;
    r.data.assign(reply->message, reply->message + reply->length);
    r.status.assign((const char *)status->message, status->length);
    if ((size_t)status->length > longest_status.size()) {
        longest_status = r.status;
    }
    int guard = 0;
    while (!reply->last_part && (guard++ < 10)) {
        net.get_more_data(&reply, &status);
        r.data.insert(r.data.end(), reply->message, reply->message + reply->length);
        r.status.append((const char *)status->message, status->length);
    }
    return r;
}

static bytes B(std::initializer_list<int> v)
{
    bytes b;
    for (int x : v) {
        b.push_back((uint8_t)x);
    }
    return b;
}

static bytes cat(bytes a, const bytes &b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

static bytes S(const std::string &s)
{
    return bytes(s.begin(), s.end());
}

static bytes PIN(uint8_t fill = 0x5A)
{
    return bytes(32, fill);
}

static bytes open_cmd(uint8_t trust, uint8_t flags, const std::string &tail, const bytes &pin = bytes(),
                      uint16_t port = 443, uint8_t first = 0x03)
{
    bytes c = B({ first, 0x21, port & 0xFF, port >> 8, trust, flags });
    c = cat(c, pin);
    return cat(c, S(tail));
}

static bytes close_cmd(int h)
{
    return B({ 0x03, 0x09, h });
}

static void fresh(void)
{
    world_reset();
    reset_c64();
    world_module.calls.clear();
    world_module.close_alls = 0;
    for (int i = 0; i < 16; i++) {
        world_socks[i] = FakeSock();
        world_socks[i].srv.saw_alert = -1;
        world_socks[i].srv.flight = 2000;
        world_socks[i].srv.delay_ms = 20;
        world_socks[i].srv.chunk = 1460;
    }
}


static int open_status(std::string *status)
{
    Res r = run(open_cmd(0, 0, "example.com"));
    *status = r.status;
    return r.data.size() == 8 ? r.data[0] : -1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    world_reset_hook = [] { net.c64_reset(); };
    world_abort_hook = [] { if (net.cancel) { *net.cancel = true; } };
    std::string st;
    uint8_t a, b, c;
    uint16_t ta, tb, tc;

    fresh();
    check(NetworkTarget::tls_lend_slot(&a, &ta) && a == 1 && ta >= 0x8000, "lend: the highest slot first, a tag apart from target 3's");
    check(NetworkTarget::tls_lend_slot(&b, &tb) && b == 0 && tb != ta, "lend: then the other, under another tag");
    check(!NetworkTarget::tls_lend_slot(&c, &tc), "lend: none left");
    size_t calls = world_module.calls.size();
    int dns = world_dns_calls;
    check(open_status(&st) < 0 && st == "91,TLS SESSIONS IN USE", "OPEN with both slots lent -> 91 (got %s)", st.c_str());
    check(world_module.calls.size() == calls && world_dns_calls == dns, "... and the module and DNS were not touched");
    NetworkTarget::tls_return_slot(b);
    int h = open_status(&st);
    check(h >= 0 && st == "00,OK" && net.tls[0].used && !net.tls[1].used, "OPEN takes the returned slot 0 (got %s)", st.c_str());
    check(open_status(&st) < 0 && st == "91,TLS SESSIONS IN USE", "OPEN while the other slot is lent -> 91 (got %s)", st.c_str());
    check(!NetworkTarget::tls_lend_slot(&c, &tc), "lend: slot 0 is held by an OPEN_TLS, slot 1 still lent");
    NetworkTarget::tls_return_slot(a);
    check(NetworkTarget::tls_lend_slot(&c, &tc) && c == 1 && tc != ta, "lend: the returned slot 1 again, under a new tag");
    NetworkTarget::tls_return_slot(c);
    run(close_cmd(h));
    check(NetworkTarget::tls_lend_slot(&c, &tc) && c == 1 && NetworkTarget::tls_lend_slot(&a, &ta) && a == 0,
          "lend: both slots once the OPEN_TLS session is closed");
    NetworkTarget::tls_return_slot(c);
    NetworkTarget::tls_return_slot(a);
    // A failed OPEN gives its slot back to the table, and a lent slot comes back after an OPEN that failed.
    fresh();
    world_dns.push_back({ "nowhere.example", DNS_ERR_VAL, 0, 0 });
    Res r = run(open_cmd(0, 0, "nowhere.example"));
    check(r.status != "00,OK" && !net.tls[0].used && NetworkTarget::tls_lend_slot(&a, &ta) && a == 1 && NetworkTarget::tls_lend_slot(&b, &tb) && b == 0,
          "a failed OPEN leaves both slots free to lend (got %s)", r.status.c_str());
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
