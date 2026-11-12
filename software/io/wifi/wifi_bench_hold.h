#ifndef WIFI_BENCH_HOLD_H_
#define WIFI_BENCH_HOLD_H_

/*
 * BENCH ONLY, never for upstream. The host side of the module command CMD_BENCH_HOLD_RX (0xB1): the WiFi
 * module stops reading its UART RX FIFO for a set time, so its hardware RTS stalls the host's WiFi UART TX while the
 * radio, the events and the air frames keep running (the module side is in the rpc_dispatch.c and
 * my_uart.c of software/wifi/raw_u64, raw_c3 and software/u64ctrl, cmd_bench_hold_rx).
 *
 * Wire format (rpc_header_t is 4 bytes: command, thread, sequence):
 *   request  { rpc_header_t hdr; uint32_t ms; }                 8 bytes. ms: 1..10000, larger is clamped to 10000,
 *                                                               0 = release the hold now
 *   reply    { rpc_header_t hdr; int esp_err; uint32_t held_ms; }  12 bytes: held_ms is the clamped value. The module queues
 *            the reply BEFORE the hold starts. A module without the command answers rpc_espcmd_resp (hdr + esp_err =
 *            ESP_ERR_NOT_SUPPORTED, 0x106) = 8 bytes.
 *
 * The UCI command that carries it is in bench_hold_ctrl.h.
 *
 * Needs rpc_header_t (rpc_calls.h) declared before it is included. If the module tree's rpc_calls.h one day defines
 * CMD_BENCH_HOLD_RX itself, it also has to define rpc_bench_hold_rx_req / _resp with this layout (only these names are
 * used here).
 */

#include "bench_hold_ctrl.h"

#ifndef CMD_BENCH_HOLD_RX
#define CMD_BENCH_HOLD_RX 0xB1

typedef struct {
    rpc_header_t hdr;
    bench_u32_t ms;
} rpc_bench_hold_rx_req;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    bench_u32_t held_ms;
} rpc_bench_hold_rx_resp;
#endif

#if defined(__cplusplus) && __cplusplus >= 201103L // BENCH r4: the U64 updater builds wifi_cmd.cc as C++98
static_assert(sizeof(rpc_bench_hold_rx_req) == 8, "CMD_BENCH_HOLD_RX request is 8 bytes");
static_assert(sizeof(rpc_bench_hold_rx_resp) == 12, "CMD_BENCH_HOLD_RX reply is 12 bytes");
#endif

// ms as the module takes it: 0 releases, 1..10000 holds, more is 10000
static inline uint32_t bench_hold_clamp(uint32_t ms)
{
    return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : ms;
}

// What the module answered: 'size' bytes at 'data'. BENCH_HOLD_RC_OK with esp_err and held_ms set (an 8 byte error answer
// has held_ms 0), else BENCH_HOLD_RC_SHORT.
static inline int bench_hold_rx_parse(const uint8_t *data, int size, int *esp_err, uint32_t *held_ms)
{
    if (size < (int)(sizeof(rpc_header_t) + sizeof(int))) {
        return BENCH_HOLD_RC_SHORT;
    }
    int err;
    memcpy(&err, data + sizeof(rpc_header_t), sizeof(err));
    bench_u32_t held = 0;
    if (size >= (int)sizeof(rpc_bench_hold_rx_resp)) {
        memcpy(&held, data + sizeof(rpc_header_t) + sizeof(int), sizeof(held));
    } else if (err == 0) {
        return BENCH_HOLD_RC_SHORT; // a success answer without held_ms is not this command's reply
    }
    *esp_err = err;
    *held_ms = held;
    return BENCH_HOLD_RC_OK;
}

#endif /* WIFI_BENCH_HOLD_H_ */
