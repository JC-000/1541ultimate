/*
 * wifi_random.h
 *
 * Hardware random bytes from the WiFi module. Kept apart from wifi_cmd.h so
 * that its users do not see the module's RPC definitions in rpc_calls.h, some
 * of which (CMD_IDENTIFY) clash with the command interface's.
 */

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

// Checks the size bytes at reply as the module's answer to request sequence
// for len bytes. Returns 0 and copies the bytes to buf, and the entropy source
// to source unless it is NULL, only for a well formed answer that carries
// exactly len bytes from a real source. Returns one of the codes above, or
// the one below, and touches neither otherwise.
int wifi_random_take_reply(const uint8_t *reply, int size, uint16_t sequence,
                           uint8_t *buf, uint16_t len, uint8_t *source);
#define WIFI_RANDOM_FOREIGN   5 // not the answer to this request

#endif /* WIFI_RANDOM_H_ */
