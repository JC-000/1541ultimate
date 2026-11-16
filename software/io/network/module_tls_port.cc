/*
 * module_tls_port.cc
 *
 * The firmware side of target 6's HTTPS over the WiFi module (software/network/module_tls_http.cc): lwIP's
 * DNS and sockets, the clock, and the module's session slots, which are shared with target 3
 * (NetworkTarget::tls_lend_slot). It is target 3's own transport (network_target_tls.cc), run by the
 * HTTP target's worker task.
 */

#include "module_tls_http.h"

#ifdef MODULE_TLS_HTTP

#include "network_target.h"
#include "network_interface.h"
#include "socket.h"
#include "lwip/opt.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "netdb.h"
#include <errno.h>
#include <string.h>
#include "FreeRTOS.h"
#include "task.h"
#include "sntp_time.h"

#define PORT_EARLIEST_TIME   1735689600u // 2025-01-01: an SNTP time before this is not one
#define PORT_SLICE_MS        100
#define PORT_SNDTIMEO_MS     500         // caps lwIP's close when it cannot get memory for the FIN
#define PORT_EXCHANGE_MS     30000
#define PORT_CLEANUP_MS      1000

static bool port_stopped(const wifi_tls_cancel_t *cancel)
{
    return cancel && cancel->cancelled && cancel->cancelled(cancel->context);
}

// One lookup at a time on this task's side, known by its sequence number as in target 3.
static struct {
    uint32_t cur_seq;
    ip_addr_t addr;
    uint8_t state; // 0 pending, 1 found, 2 failed
} port_dns;

static void port_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg)
{
    // On the tcpip thread, which holds the core lock.
    if ((uint32_t)(uintptr_t)arg != port_dns.cur_seq) {
        return;
    }
    if (ipaddr) {
        port_dns.addr = *ipaddr;
        port_dns.state = 1;
    } else {
        port_dns.state = 2;
    }
}

class FirmwareModuleTlsPort : public ModuleTlsPort
{
    static uint32_t ticks_ms() { return (uint32_t)xTaskGetTickCount() * portTICK_PERIOD_MS; }

    // Waits at most budget (and a slice) for the socket; true when it is ready.
    bool wait(int sock, bool for_write, uint32_t budget_ms)
    {
        if (budget_ms > PORT_SLICE_MS) {
            budget_ms = PORT_SLICE_MS;
        }
        fd_set fds, errs;
        FD_ZERO(&fds);
        FD_ZERO(&errs);
        FD_SET(sock, &fds);
        FD_SET(sock, &errs);
        struct timeval tv;
        tv.tv_sec = budget_ms / 1000;
        tv.tv_usec = (budget_ms % 1000) * 1000;
        return lwip_select(sock + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, &errs, &tv) > 0;
    }
    int resolve(const char *host, uint32_t end, const wifi_tls_cancel_t *cancel, uint32_t *address)
    {
        ip_addr_t found;
        LOCK_TCPIP_CORE();
        uint32_t seq = ++port_dns.cur_seq;
        port_dns.state = 0;
        err_t err = dns_gethostbyname(host, &found, port_dns_found, (void *)(uintptr_t)seq);
        UNLOCK_TCPIP_CORE();
        if (err == ERR_OK) {
            *address = ip4_addr_get_u32(ip_2_ip4(&found));
            return 0;
        }
        if (err != ERR_INPROGRESS) {
            return EHOSTUNREACH;
        }
        while (true) {
            LOCK_TCPIP_CORE();
            uint8_t state = port_dns.state;
            found = port_dns.addr;
            UNLOCK_TCPIP_CORE();
            if (state == 1) {
                *address = ip4_addr_get_u32(ip_2_ip4(&found));
                return 0;
            }
            if (state == 2 || port_stopped(cancel) || (int32_t)(end - now_ms()) <= 0) {
                return EHOSTUNREACH;
            }
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
public:
    bool module_ready() override { return wifi_tls_module_available(); }
    uint32_t now_ms() override { return ticks_ms(); }
    void sleep_ms(uint32_t ms) override { vTaskDelay(pdMS_TO_TICKS(ms) ? pdMS_TO_TICKS(ms) : 1); }
    uint32_t utc_now() override
    {
        uint32_t now = sntp_utc_now();
        return now >= PORT_EARLIEST_TIME ? now : 0;
    }
    bool take_slot(uint8_t *slot, uint16_t *tag) override { return NetworkTarget::tls_lend_slot(slot, tag); }
    void give_slot(uint8_t slot) override { NetworkTarget::tls_return_slot(slot); }

    int tcp_connect(const char *host, uint16_t port, uint32_t budget_ms, const wifi_tls_cancel_t *cancel, int *handle) override
    {
        uint32_t end = now_ms() + budget_ms;
        uint32_t address = 0;
        int error = resolve(host, end, cancel, &address);
        if (error) {
            return error;
        }
        int sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return ENOBUFS;
        }
        int on = 1;
        lwip_ioctl(sock, FIONBIO, &on);
        lwip_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = PORT_SNDTIMEO_MS * 1000;
        lwip_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_len = sizeof(addr);
        addr.sin_family = AF_INET;
        addr.sin_port = PP_HTONS(port);
        addr.sin_addr.s_addr = address;
        while (lwip_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            error = errno;
            if (error == EISCONN) {
                break;
            }
            if ((error != EINPROGRESS) && (error != EALREADY)) {
                lwip_close(sock);
                return error;
            }
            int32_t left = (int32_t)(end - now_ms());
            if (port_stopped(cancel) || left <= 0) {
                lwip_close(sock);
                return ETIMEDOUT;
            }
            wait(sock, true, (uint32_t)left);
        }
        *handle = sock;
        return 0;
    }
    int tcp_send(int sock, const uint8_t *data, int length, uint32_t budget_ms, const wifi_tls_cancel_t *cancel) override
    {
        uint32_t end = now_ms() + budget_ms;
        while (length > 0) {
            int sent = lwip_send(sock, data, length, MSG_DONTWAIT);
            if (sent > 0) {
                data += sent;
                length -= sent;
                continue;
            }
            if ((sent < 0) && (errno != EWOULDBLOCK) && (errno != EAGAIN)) {
                return errno;
            }
            int32_t left = (int32_t)(end - now_ms());
            if (port_stopped(cancel)) {
                return ECANCELED;
            }
            if (left <= 0) {
                return ETIMEDOUT;
            }
            wait(sock, true, (uint32_t)left);
        }
        return 0;
    }
    int tcp_recv(int sock, uint8_t *buffer, int room, uint32_t budget_ms, const wifi_tls_cancel_t *cancel) override
    {
        if (!port_stopped(cancel) && !wait(sock, false, budget_ms)) {
            return 0;
        }
        int n = lwip_recv(sock, buffer, room, MSG_DONTWAIT);
        if (n > 0) {
            return n;
        }
        if (n == 0) {
            return -1;
        }
        return ((errno == EWOULDBLOCK) || (errno == EAGAIN)) ? 0 : -2;
    }
    bool is_ipv4_literal(const char *host) override
    {
        ip4_addr_t address;
        return ip4addr_aton(host, &address) != 0;
    }
    void tcp_close(int sock) override { lwip_close(sock); }
};

static FirmwareModuleTlsPort firmware_port;
static ModuleTlsHttpProvider firmware_provider(firmware_port, PORT_EXCHANGE_MS, PORT_CLEANUP_MS);

HttpSecureProvider *module_tls_https_provider()
{
    return &firmware_provider;
}

#endif // MODULE_TLS_HTTP
