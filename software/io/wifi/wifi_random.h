// wifi_random.h: hardware random bytes from the WiFi module. Apart from wifi_cmd.h so that its users do not see the
// module's RPC definitions in rpc_calls.h, some of which (CMD_IDENTIFY) clash with the command interface's.

#ifndef WIFI_RANDOM_H_
#define WIFI_RANDOM_H_

#include <stdint.h>

// Fills buf with len bytes from the module's hardware random number generator
// and returns 0, or returns one of the codes below and leaves buf untouched.
// U64 only.
int wifi_get_random(uint8_t *buf, uint16_t len, uint8_t *source);
#define WIFI_RANDOM_BUSY      1 // no answer in time; the module may be busy
#define WIFI_RANDOM_REFUSED   2 // the module refused, or had no entropy source
#define WIFI_RANDOM_INVALID   3 // the answer is not a well formed reply
#define WIFI_RANDOM_NO_MODULE 4 // the module application is not running

// Checks the size bytes at reply as the module's answer to request sequence for len bytes. Only for a well formed
// answer with exactly len bytes from a real source does it return 0 and copy the bytes to buf (and the source to
// source unless NULL); otherwise it returns one of the codes above or below and touches neither.
int wifi_random_take_reply(const uint8_t *reply, int size, uint16_t sequence,
                           uint8_t *buf, uint16_t len, uint8_t *source);
#define WIFI_RANDOM_FOREIGN   5 // not the answer to this request

// The UCI status number for a wifi_get_random result: 0 (OK, the bytes go out) for 0 only, 88 (busy, retry) for
// WIFI_RANDOM_BUSY, 86 (internal error) for WIFI_RANDOM_INVALID, and 87 (no entropy source) for every other value.
int wifi_random_status(int result);

// Whether a reply to GET_RANDOM may carry data for this result of
// wifi_get_random: for 0 and nothing else.
bool wifi_random_has_data(int result);

#endif /* WIFI_RANDOM_H_ */
