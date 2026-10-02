// The earlier wifi_get_random, compiled unchanged from get_random_oracle.inc as oracle_wifi_get_random, against the same
// world as the new code. Only the names that the move to wifi_dedicated.cc renamed are mapped back.
#include <stddef.h>
#include "wifi_cmd.h"
#include "wifi_random.h"
#include "world.h"

#define random_replies     dedicated_replies
#define random_waiting     dedicated_waiting
#define random_reply_t     dedicated_reply_t
#define WIFI_RANDOM_THREAD WIFI_DEDICATED_THREAD
#define wifi_get_random    oracle_wifi_get_random

int oracle_wifi_get_random(uint8_t *buf, uint16_t len, uint8_t *source);

// wifi.cc's gate, on the world's answer.
enum { eWifi_AppDetected = 4 };
static struct {
    int getState(void) { return world_ready ? eWifi_AppDetected : 0; }
} wifi;

#include "get_random_oracle.inc"
