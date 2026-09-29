/* Stand-in for ESP-IDF's esp_err.h, for the host build of esp_crt_bundle.c (limbo.c) */
#pragma once
#include <stdint.h>
#include <stdlib.h>
typedef int esp_err_t;
#define ESP_OK              0
#define ESP_ERR_NO_MEM      0x101
#define ESP_ERR_INVALID_ARG 0x102
