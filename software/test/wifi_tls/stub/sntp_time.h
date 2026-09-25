// Host stand-in for software/network/sntp_time.h, faked in spike_test.cc.
#ifndef SNTP_TIME_H_STUB
#define SNTP_TIME_H_STUB
#include <stdint.h>
uint32_t sntp_utc_now(void);
#endif
