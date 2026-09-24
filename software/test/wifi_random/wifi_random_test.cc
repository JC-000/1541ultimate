/*
 * Host side tests for the check the Nios applies to the WiFi module's answer
 * to GET_RANDOM.
 *
 *   make -C target/pc/linux/wifirandom test
 *
 * The real software/io/wifi/wifi_random.cc is compiled here, so what runs is
 * the code that ships. Each case is an answer that a broken or confused module
 * could send; none of them may hand out a single byte.
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "rpc_calls.h"
#include "wifi_random.h"

// The layout both sides agree on is asserted in wifi_random.cc itself.

#define SEQUENCE 0x1234
#define LEN      32
#define HEADER   12

static int failures;
static int checks;

static void check(int condition, const char *what)
{
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", what);
    } else {
        printf("  ok    %s\n", what);
    }
}

// Word aligned, as the data of a command_buf_t is.
static union {
    uint32_t align;
    uint8_t bytes[HEADER + 600];
} reply;

// A correct answer to request SEQUENCE for LEN bytes; returns its size.
static int build(void)
{
    memset(reply.bytes, 0, sizeof(reply.bytes));
    rpc_get_random_resp *r = (rpc_get_random_resp *)reply.bytes;
    r->hdr.command = CMD_GET_RANDOM;
    r->hdr.thread = 12;
    r->hdr.sequence = SEQUENCE;
    r->esp_err = 0;
    r->source = ENTROPY_RADIO;
    r->length = LEN;
    for (int i = 0; i < LEN; i++) {
        r->data[i] = (uint8_t)(0xA0 + i);
    }
    return HEADER + LEN;
}

static rpc_get_random_resp *answer(void)
{
    return (rpc_get_random_resp *)reply.bytes;
}

// Runs the check on the first size bytes of the reply; true when it returned
// expected and, unless that is success, left buf and source alone.
static bool outcome(int size, uint16_t len, int expected)
{
    uint8_t buf[600];
    uint8_t source = 0x55;
    memset(buf, 0xEE, sizeof(buf));
    int result = wifi_random_take_reply(reply.bytes, size, SEQUENCE, buf, len, &source);
    if (result != expected) {
        printf("        returned %d, expected %d\n", result, expected);
        return false;
    }
    if (expected == 0) {
        return (memcmp(buf, answer()->data, len) == 0) && (buf[len] == 0xEE) &&
               (source == answer()->source);
    }
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0xEE) {
            printf("        byte %d was written\n", (int)i);
            return false;
        }
    }
    return source == 0x55;
}

int main(void)
{
    int size;

    printf("The answer to this request\n");
    size = build();
    check(outcome(size, LEN, 0), "hands out exactly len bytes and the source");
    size = build();
    check(outcome(size + 100, LEN, 0), "ignores bytes the module sent beyond len");
    size = build();
    answer()->source = ENTROPY_ADC;
    check(outcome(size, LEN, 0), "hands out the source the module reported");
    size = build();
    uint8_t buf[LEN];
    check(wifi_random_take_reply(reply.bytes, size, SEQUENCE, buf, LEN, NULL) == 0,
          "accepts a NULL source");

    printf("An answer to something else\n");
    size = build();
    answer()->hdr.sequence = SEQUENCE - 1;
    check(outcome(size, LEN, WIFI_RANDOM_FOREIGN), "wrong sequence is not ours");
    size = build();
    answer()->hdr.sequence = SEQUENCE ^ 0x0100;
    check(outcome(size, LEN, WIFI_RANDOM_FOREIGN), "a sequence that differs only in its high byte is not ours");
    size = build();
    answer()->hdr.command = CMD_WIFI_GETMAC;
    check(outcome(size, LEN, WIFI_RANDOM_FOREIGN), "wrong command is not ours");
    size = build();
    check(outcome(3, LEN, WIFI_RANDOM_FOREIGN), "fewer bytes than a header is not ours");

    printf("A refusal\n");
    size = build();
    answer()->esp_err = 0x103; // ESP_ERR_INVALID_STATE
    answer()->length = 0;
    check(outcome(HEADER, LEN, WIFI_RANDOM_REFUSED), "esp_err INVALID_STATE with no bytes");
    size = build();
    answer()->esp_err = 0x103;
    check(outcome(size, LEN, WIFI_RANDOM_REFUSED), "esp_err set, even with len bytes behind it");
    size = build();
    answer()->esp_err = 0x106; // ESP_ERR_NOT_SUPPORTED, from firmware without the call
    check(outcome(8, LEN, WIFI_RANDOM_REFUSED), "the 8 byte answer of old module firmware");
    size = build();
    answer()->source = ENTROPY_NONE;
    check(outcome(size, LEN, WIFI_RANDOM_REFUSED), "OK without an entropy source");

    printf("A malformed answer\n");
    size = build();
    check(outcome(7, LEN, WIFI_RANDOM_INVALID), "too short to hold esp_err");
    size = build();
    check(outcome(HEADER - 1, LEN, WIFI_RANDOM_INVALID), "OK but too short to hold the header");
    size = build();
    answer()->length = LEN - 1;
    check(outcome(size, LEN, WIFI_RANDOM_INVALID), "fewer bytes announced than asked");
    size = build();
    answer()->length = LEN + 1;
    check(outcome(size + 1, LEN, WIFI_RANDOM_INVALID), "more bytes announced than asked");
    size = build();
    check(outcome(size - 1, LEN, WIFI_RANDOM_INVALID), "fewer bytes received than announced");
    size = build();
    answer()->length = 0;
    check(outcome(HEADER, LEN, WIFI_RANDOM_INVALID), "OK with no bytes at all");

    printf("The UCI status of a result\n");
    check(wifi_random_status(0) == 0, "0 is OK");
    check(wifi_random_status(WIFI_RANDOM_BUSY) == 88, "busy is 88");
    check(wifi_random_status(WIFI_RANDOM_INVALID) == 86, "an invalid reply is 86");
    check(wifi_random_status(WIFI_RANDOM_REFUSED) == 87, "a refusal is 87");
    check(wifi_random_status(WIFI_RANDOM_NO_MODULE) == 87, "no module is 87");
    check(wifi_random_status(WIFI_RANDOM_FOREIGN) == 87, "a foreign reply is 87");
    bool only_zero = true;
    for (int result = -1000; result <= 1000; result++) {
        if ((wifi_random_status(result) == 0) != (result == 0)) {
            only_zero = false;
        }
    }
    check(only_zero, "no result but 0 maps to OK, from -1000 to 1000");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
