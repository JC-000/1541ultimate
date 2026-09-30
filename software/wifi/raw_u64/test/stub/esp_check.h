/* engine4 host stub: what IDF's esp_crt_bundle.c takes from esp_check.h and esp_compiler.h */
#pragma once
#include <inttypes.h>
#include "esp_log.h"
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef ESP_LOGD
#define ESP_LOGD(tag, fmt, ...) do { } while (0)
#endif
