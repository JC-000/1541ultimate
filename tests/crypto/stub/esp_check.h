/* Stand-in for ESP-IDF's esp_check.h, for the host build of ESP-IDF 6's esp_crt_bundle.c
 * (limbo.c): it uses none of the checks, only what esp_check.h brings in (esp_compiler.h's
 * likely/unlikely, and the PRIu16 its log lines format with) */
#pragma once
#include <inttypes.h>
#include "esp_err.h"
#include "esp_log.h"
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
