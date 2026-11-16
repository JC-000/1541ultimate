#ifndef MODULE_TLS_HTTP_H
#define MODULE_TLS_HTTP_H

#include <stdint.h>
#include "http_connection.h"
#include "wifi_tls.h"

// Target 6 (UCI HTTP) over the WiFi module's TLS sessions, the same wifi_tls
// calls that target 3 uses. This side owns TCP (DNS, connect, ciphertext
// in and out); the module holds the keys, the CA bundle and the verification.
// Trust is always the module's CA bundle, the SNI is the URL's host, and a
// clock the module cannot trust refuses the OPEN. Nothing here ever falls back
// to a plain socket: a failure is a negative result.
#if defined(U64) && (U64 == 2) && !defined(RUNS_ON_PC)
#define MODULE_TLS_HTTP 1
#endif

// What the adapter needs from the platform besides wifi_tls_*. Waits take a
// budget and the wifi_tls cancel predicate, and return early when it says so.
class ModuleTlsPort
{
public:
    virtual ~ModuleTlsPort() {}
    virtual bool module_ready() = 0;      // wifi_tls_module_available()
    virtual uint32_t now_ms() = 0;        // monotonic, wraps
    virtual void sleep_ms(uint32_t ms) = 0;
    virtual uint32_t utc_now() = 0;       // UTC seconds, 0 when not trustworthy
    // One of the module's session slots, exclusively, until given back.
    virtual bool take_slot(uint8_t *slot, uint16_t *tag) = 0;
    virtual void give_slot(uint8_t slot) = 0;
    // DNS and TCP connect. 0 with *handle, else an error (nonzero).
    virtual int tcp_connect(const char *host, uint16_t port, uint32_t budget_ms, const wifi_tls_cancel_t *cancel,
                        int *handle) = 0;
    // 0 once all of it is sent, else an error.
    virtual int tcp_send(int handle, const uint8_t *data, int length, uint32_t budget_ms,
                     const wifi_tls_cancel_t *cancel) = 0;
    // Waits up to budget_ms for data: bytes (>0), 0 for none yet, -1 for the
    // peer's end of stream, -2 for an error.
    virtual int tcp_recv(int handle, uint8_t *buffer, int room, uint32_t budget_ms, const wifi_tls_cancel_t *cancel) = 0;
    virtual void tcp_close(int handle) = 0;
    // lwIP's own predicate for an IPv4 literal (ip4addr_aton: 127.1, 0x7f.0.0.1, a trailing space or \v), as target 3
    // asks it. host is NUL-terminated.
    virtual bool is_ipv4_literal(const char *host) = 0;
};

class ModuleTlsHttpProvider : public HttpSecureProvider
{
public:
    // exchange_ms bounds a whole request (open, every read and write);
    // cleanup_ms bounds the CLOSE and the close_notify after it.
    ModuleTlsHttpProvider(ModuleTlsPort& port, uint32_t exchange_ms, uint32_t cleanup_ms);
    bool available() const override;
    HttpConnection *create_connection(const OperationCancellation& cancellation) override;
private:
    class Connection;
    friend class Connection;
    ModuleTlsPort& port_;
    uint32_t exchange_ms_, cleanup_ms_;
    volatile bool occupied_;
    ModuleTlsHttpProvider(const ModuleTlsHttpProvider&) = delete;
    ModuleTlsHttpProvider& operator=(const ModuleTlsHttpProvider&) = delete;
};

#ifdef MODULE_TLS_HTTP
// The provider for the firmware, on the WiFi module, stable for its lifetime.
HttpSecureProvider *module_tls_https_provider();
#endif

#endif
