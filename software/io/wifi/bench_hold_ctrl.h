#ifndef BENCH_HOLD_CTRL_H_
#define BENCH_HOLD_CTRL_H_

/*
 * BENCH ONLY, never for upstream. The UCI side of the X15 leg's module command CMD_BENCH_HOLD_RX (wifi_bench_hold.h has
 * the wire format and the whole description). No dependency on the RPC headers, so network_target.cc can include it.
 *
 * UCI network target (target 3), command NET_CMD_BENCH_HOLD_RX = 0xE5 (network_target.h; RPC-REGISTRY.md):
 *   command  03 E5 <ms u32 LE>                                  6 bytes, [0] target, [1] command
 *   reply    <esp_err i32 LE> <held_ms u32 LE>                  8 bytes of data, status "00,OK"; esp_err is whatever the
 *            module answered (0 = held), except that NOT_SUPPORTED is an error string, not data.
 *   status   81,INVALID PARAMS      command length is not 6
 *            98,NO WIFI UART        no WiFi module on this board (esp32.uart NULL)
 *            98,NO TX BUFFER        no UART TX buffer within 5 s: nothing was sent
 *            98,NO REPLY SLOT       no free RPC reply slot: nothing was sent
 *            01,HOLD SENT NO REPLY  the request went out, no answer within held ms + 1 s: the hold probably ran;
 *                                   confirm with the counters (MODCTR rts_stall / rx_fifo_ovf, NETCTR refused=)
 *            98,BAD WIFI REPLY      a reply shorter than 8 bytes (or 8 bytes with esp_err 0)
 *            99,HOLD NOT SUPPORTED  the module does not have the command (bench IDENT missing)
 * The module queues its reply before the hold starts, so the reply normally comes at once; the host still waits up to
 * held ms + 1 s for it (bench only: at most 11 s on the UCI side), in case it comes only after the hold.
 */

#include <stdint.h>
#include <string.h>

// The wire format is 32 bit little endian words; the host test of wifi_cmd.cc (software/test/wifi_reply/stubs/FreeRTOS.h)
// redefines uint32_t as uintptr_t, so everything that is copied to or from the wire uses this type
typedef unsigned int bench_u32_t;
#if defined(__cplusplus) && __cplusplus >= 201103L // BENCH r4: the U64 updater builds wifi_cmd.cc as C++98
static_assert(sizeof(bench_u32_t) == 4 && sizeof(int) == 4, "the wire words are 4 bytes");
#endif

#define BENCH_HOLD_MS_MAX          10000
#define BENCH_HOLD_RPC_SLACK_MS    1000 // the reply wait is the clamped hold plus this
#define BENCH_HOLD_NOT_SUPPORTED   0x106 // ESP_ERR_NOT_SUPPORTED

#define BENCH_HOLD_RC_OK     0
#define BENCH_HOLD_RC_NONE  (-1)         // sent, no reply within held ms + BENCH_HOLD_RPC_SLACK_MS
#define BENCH_HOLD_RC_NO_UART (-3)       // no WiFi module (esp32.uart NULL)
#define BENCH_HOLD_RC_NO_BUF  (-4)       // no UART TX buffer: nothing sent
#define BENCH_HOLD_RC_NO_SLOT (-5)       // no RPC reply slot: nothing sent
#define BENCH_HOLD_RC_SHORT (-2)         // a reply that is not an answer to this command

#define BENCH_HOLD_TXT_OK            "00,OK"
#define BENCH_HOLD_TXT_BAD_PARAMS    "81,INVALID PARAMS"
#define BENCH_HOLD_TXT_NO_REPLY      "01,HOLD SENT NO REPLY"
#define BENCH_HOLD_TXT_NO_UART       "98,NO WIFI UART"
#define BENCH_HOLD_TXT_NO_BUF        "98,NO TX BUFFER"
#define BENCH_HOLD_TXT_NO_SLOT       "98,NO REPLY SLOT"
#define BENCH_HOLD_TXT_BAD_REPLY     "98,BAD WIFI REPLY"
#define BENCH_HOLD_TXT_NOT_SUPPORTED "99,HOLD NOT SUPPORTED"

#define BENCH_HOLD_UCI_LEN 6 // target, command, ms u32

typedef int (*bench_hold_call_fn)(uint32_t ms, int *esp_err, uint32_t *held_ms);

// The RPC (wifi_cmd.cc): BENCH_HOLD_RC_OK, _SHORT, _NONE (sent, no reply), _NO_UART, _NO_BUF or _NO_SLOT.
int wifi_bench_hold_rx(uint32_t ms, int *esp_err, uint32_t *held_ms);

// The UCI command NET_CMD_BENCH_HOLD_RX: 'msg' is the command (length 'len', [0] target, [1] command, [2..5] ms). Returns
// 1 with the 8 data bytes in 'out' (*outlen = 8) when the module answered, else 0 and *outlen = 0. 'status' (at least 32
// bytes) always gets the status text.
static inline int bench_hold_rx_ctrl(const uint8_t *msg, int len, uint8_t *out, int *outlen, char *status, bench_hold_call_fn call)
{
    *outlen = 0;
    if (len != BENCH_HOLD_UCI_LEN) {
        strcpy(status, BENCH_HOLD_TXT_BAD_PARAMS);
        return 0;
    }
    bench_u32_t ms;
    memcpy(&ms, msg + 2, sizeof(ms));
    int esp_err = 0;
    uint32_t held = 0;
    int rc = call(ms, &esp_err, &held);
    if (rc == BENCH_HOLD_RC_SHORT) {
        strcpy(status, BENCH_HOLD_TXT_BAD_REPLY);
        return 0;
    }
    if (rc != BENCH_HOLD_RC_OK) {
        strcpy(status, (rc == BENCH_HOLD_RC_NO_UART) ? BENCH_HOLD_TXT_NO_UART :
                       (rc == BENCH_HOLD_RC_NO_BUF)  ? BENCH_HOLD_TXT_NO_BUF :
                       (rc == BENCH_HOLD_RC_NO_SLOT) ? BENCH_HOLD_TXT_NO_SLOT : BENCH_HOLD_TXT_NO_REPLY);
        return 0;
    }
    if (esp_err == BENCH_HOLD_NOT_SUPPORTED) {
        strcpy(status, BENCH_HOLD_TXT_NOT_SUPPORTED);
        return 0;
    }
    bench_u32_t held_word = held;
    memcpy(out, &esp_err, sizeof(esp_err));
    memcpy(out + sizeof(esp_err), &held_word, sizeof(held_word));
    *outlen = (int)(sizeof(esp_err) + sizeof(held_word));
    strcpy(status, BENCH_HOLD_TXT_OK);
    return 1;
}

#endif /* BENCH_HOLD_CTRL_H_ */
