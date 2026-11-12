// BENCH ONLY. The host side of CMD_BENCH_HOLD_RX (0xB1) for the X15 leg: the UCI command 0xE5 of the network target
// (bench_hold_ctrl.h, the part that decides what the harness reads back) and the wire format and reply parser of the
// RPC (wifi_bench_hold.h). The RPC itself (BUFARGS / TRANSMIT_T, the 1 s bound, the request bytes on the UART) is tested in
// target/pc/linux/wifireply against the real wifi_cmd.cc; the case in network_target.cc and the module are not built here.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include "../../usb/tests/host_test/host_test.h"

// rpc_header_t of the module trees (rpc_calls.h)
typedef struct {
    uint8_t command;
    uint8_t thread;
    uint16_t sequence;
} rpc_header_t;

#include "bench_hold_ctrl.h"
#include "wifi_bench_hold.h"

namespace {

int calls;
uint32_t call_ms;
int ret_rc;
int ret_err;
uint32_t ret_held;

int fake_call(uint32_t ms, int *esp_err, uint32_t *held_ms)
{
    calls++;
    call_ms = ms;
    if (ret_rc == BENCH_HOLD_RC_OK) {
        *esp_err = ret_err;
        *held_ms = ret_held;
    }
    return ret_rc;
}

void reset()
{
    calls = 0;
    call_ms = 0xDEAD;
    ret_rc = BENCH_HOLD_RC_OK;
    ret_err = 0;
    ret_held = 3000;
}

struct Result {
    int have_data;
    int outlen;
    uint8_t out[16];
    char status[64];
};

// 03 E5 <ms u32 LE>, as the harness sends it
Result uci(uint32_t ms, int len = 6)
{
    uint8_t msg[8] = { 3, 0xE5, (uint8_t)ms, (uint8_t)(ms >> 8), (uint8_t)(ms >> 16), (uint8_t)(ms >> 24), 0xAA, 0xAA };
    Result r;
    memset(&r, 0x55, sizeof(r));
    r.outlen = 99;
    r.have_data = bench_hold_rx_ctrl(msg, len, r.out, &r.outlen, r.status, fake_call);
    return r;
}

} // namespace

// ---- the wire format ---------------------------------------------------------------------------------------------

TEST(HoldWire, the_request_is_8_bytes_and_the_reply_12)
{
    EXPECT_EQ((int)sizeof(rpc_bench_hold_rx_req), 8);
    EXPECT_EQ((int)offsetof(rpc_bench_hold_rx_req, ms), 4);
    EXPECT_EQ((int)sizeof(rpc_bench_hold_rx_resp), 12);
    EXPECT_EQ((int)offsetof(rpc_bench_hold_rx_resp, esp_err), 4);
    EXPECT_EQ((int)offsetof(rpc_bench_hold_rx_resp, held_ms), 8);
    EXPECT_EQ((int)CMD_BENCH_HOLD_RX, 0xB1);
}

TEST(HoldWire, ms_is_clamped_to_10000_and_zero_releases)
{
    EXPECT_EQ(bench_hold_clamp(0), (uint32_t)0);
    EXPECT_EQ(bench_hold_clamp(1), (uint32_t)1);
    EXPECT_EQ(bench_hold_clamp(3000), (uint32_t)3000);
    EXPECT_EQ(bench_hold_clamp(9999), (uint32_t)9999);
    EXPECT_EQ(bench_hold_clamp(10000), (uint32_t)10000);
    EXPECT_EQ(bench_hold_clamp(10001), (uint32_t)10000);
    EXPECT_EQ(bench_hold_clamp(0xFFFFFFFFu), (uint32_t)10000);
}

TEST(HoldWire, a_full_reply_gives_esp_err_and_held_ms)
{
    const uint8_t reply[12] = { 0xB1, 3, 7, 0, 0, 0, 0, 0, 0xB8, 0x0B, 0, 0 };
    int err = -5;
    uint32_t held = 0;
    EXPECT_EQ(bench_hold_rx_parse(reply, 12, &err, &held), BENCH_HOLD_RC_OK);
    EXPECT_EQ(err, 0);
    EXPECT_EQ(held, (uint32_t)3000);
}

TEST(HoldWire, esp_err_is_signed_and_held_ms_is_the_third_word)
{
    const uint8_t reply[14] = { 0xB1, 3, 7, 0, 0xFE, 0xFF, 0xFF, 0xFF, 0x10, 0x27, 0, 0, 0xEE, 0xEE };
    int err = 0;
    uint32_t held = 0;
    EXPECT_EQ(bench_hold_rx_parse(reply, 14, &err, &held), BENCH_HOLD_RC_OK);  // longer than the layout: still an answer
    EXPECT_EQ(err, -2);
    EXPECT_EQ(held, (uint32_t)10000);
}

TEST(HoldWire, a_module_without_the_command_answers_8_bytes_with_not_supported)
{
    const uint8_t reply[8] = { 0xB1, 3, 7, 0, 0x06, 0x01, 0, 0 };
    int err = 0;
    uint32_t held = 123;
    EXPECT_EQ(bench_hold_rx_parse(reply, 8, &err, &held), BENCH_HOLD_RC_OK);
    EXPECT_EQ(err, 0x106);
    EXPECT_EQ(held, (uint32_t)0);
}

TEST(HoldWire, a_reply_cut_short_is_not_an_answer)
{
    const uint8_t reply[12] = { 0xB1, 3, 7, 0, 0x06, 0x01, 0, 0, 0xB8, 0x0B, 0, 0 };
    int err = 9;
    uint32_t held = 9;
    for (int size = 7; size >= -1; size--) {
        EXPECT_EQ(bench_hold_rx_parse(reply, size, &err, &held), BENCH_HOLD_RC_SHORT);
    }
    EXPECT_EQ(err, 9);        // nothing was written
    EXPECT_EQ(held, (uint32_t)9);
}

TEST(HoldWire, an_8_to_11_byte_reply_with_esp_err_zero_is_not_this_commands_answer)
{
    const uint8_t reply[12] = { 0xB1, 3, 7, 0, 0, 0, 0, 0, 0xB8, 0x0B, 0, 0 };
    int err = 9;
    uint32_t held = 9;
    for (int size = 8; size <= 11; size++) {
        EXPECT_EQ(bench_hold_rx_parse(reply, size, &err, &held), BENCH_HOLD_RC_SHORT);
    }
    EXPECT_EQ(err, 9);
}

// ---- the UCI command ------------------------------------------------------------------------------------------------

TEST(HoldUci, the_command_is_03_E5_and_ms_u32_little_endian)
{
    reset();
    uci(3000);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(call_ms, (uint32_t)3000);
    uci(0x01020304u);
    EXPECT_EQ(call_ms, (uint32_t)0x01020304u);   // the RPC clamps (wifi_bench_hold_rx), the UCI layer passes it on as it is
    uci(0);
    EXPECT_EQ(call_ms, (uint32_t)0);
}

TEST(HoldUci, an_answer_is_esp_err_then_held_ms_8_bytes_and_ok)
{
    reset();
    ret_err = 0;
    ret_held = 3000;
    Result r = uci(5000);
    EXPECT_EQ(r.have_data, 1);
    EXPECT_EQ(r.outlen, 8);
    const uint8_t expect[8] = { 0, 0, 0, 0, 0xB8, 0x0B, 0, 0 };
    EXPECT_TRUE(memcmp(r.out, expect, 8) == 0);
    EXPECT_TRUE(std::string(r.status) == "00,OK");
}

TEST(HoldUci, another_esp_err_is_data_not_an_error_string)
{
    reset();
    ret_err = 0x103;   // ESP_ERR_INVALID_STATE
    ret_held = 0;
    Result r = uci(1000);
    EXPECT_EQ(r.have_data, 1);
    EXPECT_EQ(r.outlen, 8);
    const uint8_t expect[8] = { 0x03, 0x01, 0, 0, 0, 0, 0, 0 };
    EXPECT_TRUE(memcmp(r.out, expect, 8) == 0);
    EXPECT_TRUE(std::string(r.status) == "00,OK");
    ret_err = -1;
    r = uci(1000);
    const uint8_t neg[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
    EXPECT_TRUE(memcmp(r.out, neg, 8) == 0);
}

TEST(HoldUci, not_supported_is_an_error_string)
{
    reset();
    ret_err = 0x106;
    ret_held = 0;
    Result r = uci(1000);
    EXPECT_EQ(r.have_data, 0);
    EXPECT_EQ(r.outlen, 0);
    EXPECT_TRUE(std::string(r.status) == "99,HOLD NOT SUPPORTED");
    EXPECT_EQ(r.out[0], 0x55);   // no data written
}

TEST(HoldUci, each_way_of_failing_has_its_own_status)
{
    const int rcs[] = { BENCH_HOLD_RC_NONE, BENCH_HOLD_RC_NO_UART, BENCH_HOLD_RC_NO_BUF, BENCH_HOLD_RC_NO_SLOT };
    const char *want[] = { "01,HOLD SENT NO REPLY", "98,NO WIFI UART", "98,NO TX BUFFER", "98,NO REPLY SLOT" };
    for (unsigned i = 0; i < sizeof(rcs) / sizeof(rcs[0]); i++) {
        reset();
        ret_rc = rcs[i];
        Result r = uci(1000);
        EXPECT_EQ(r.have_data, 0);
        EXPECT_EQ(r.outlen, 0);
        EXPECT_TRUE(std::string(r.status) == want[i]);
        EXPECT_EQ(r.out[0], 0x55);
    }
}

TEST(HoldUci, a_short_reply_is_an_error_string)
{
    reset();
    ret_rc = BENCH_HOLD_RC_SHORT;
    Result r = uci(1000);
    EXPECT_EQ(r.have_data, 0);
    EXPECT_EQ(r.outlen, 0);
    EXPECT_TRUE(std::string(r.status) == "98,BAD WIFI REPLY");
}

TEST(HoldUci, a_command_of_any_other_length_is_refused_without_an_rpc)
{
    reset();
    for (int len = 0; len <= 8; len++) {
        if (len == 6) {
            continue;
        }
        Result r = uci(1000, len);
        EXPECT_EQ(r.have_data, 0);
        EXPECT_EQ(r.outlen, 0);
        EXPECT_TRUE(std::string(r.status) == "81,INVALID PARAMS");
    }
    EXPECT_EQ(calls, 0);
}

TEST(HoldUci, every_status_text_fits_the_documented_buffer_and_starts_with_a_two_digit_code)
{
    const char *texts[] = { BENCH_HOLD_TXT_OK, BENCH_HOLD_TXT_BAD_PARAMS, BENCH_HOLD_TXT_NO_REPLY, BENCH_HOLD_TXT_BAD_REPLY,
                            BENCH_HOLD_TXT_NO_UART, BENCH_HOLD_TXT_NO_BUF, BENCH_HOLD_TXT_NO_SLOT,
                            BENCH_HOLD_TXT_NOT_SUPPORTED };
    for (unsigned i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        EXPECT_TRUE(strlen(texts[i]) < 32);
        EXPECT_TRUE(texts[i][0] >= '0' && texts[i][0] <= '9' && texts[i][1] >= '0' && texts[i][1] <= '9' && texts[i][2] == ',');
    }
}
