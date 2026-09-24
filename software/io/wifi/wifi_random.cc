/*
 * wifi_random.cc
 *
 * Checks the WiFi module's answer to a GET_RANDOM request. Free of FreeRTOS and
 * of the UART driver, so that software/test/wifi_random tests what ships.
 */

#include <stddef.h>
#include <string.h>
#include "rpc_calls.h"
#include "wifi_random.h"

// ENTROPY_NONE of the module's entropy_source_t: bytes drawn while the
// generator had no entropy source are refused even when esp_err says OK.
#define SOURCE_NONE 0

int wifi_random_take_reply(const uint8_t *reply, int size, uint16_t sequence,
                           uint8_t *buf, uint16_t len, uint8_t *source)
{
    const rpc_get_random_resp *result = (const rpc_get_random_resp *)reply;
    const int with_error = offsetof(rpc_get_random_resp, source);
    const int header = offsetof(rpc_get_random_resp, data);

    if ((size < (int)sizeof(rpc_header_t)) || (result->hdr.command != CMD_GET_RANDOM) ||
            (result->hdr.sequence != sequence)) {
        return WIFI_RANDOM_FOREIGN;
    }
    if (size < with_error) {
        return WIFI_RANDOM_INVALID;
    }
    if (result->esp_err != 0) {
        return WIFI_RANDOM_REFUSED;
    }
    if (size < header) {
        return WIFI_RANDOM_INVALID;
    }
    if (result->source == SOURCE_NONE) {
        return WIFI_RANDOM_REFUSED;
    }
    if ((result->length != len) || (size < header + len)) {
        return WIFI_RANDOM_INVALID;
    }
    memcpy(buf, result->data, len);
    if (source) {
        *source = result->source;
    }
    return 0;
}
