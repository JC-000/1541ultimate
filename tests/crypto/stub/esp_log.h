/* Stand-in for ESP-IDF's esp_log.h, for the host build of esp_crt_bundle.c (limbo.c): quiet */
#pragma once
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
/* esp_crt_bundle.c reads this sdkconfig option; the derived configuration brings the sdkconfig's
 * value in with mbedtls/ssl.h, and a given configuration gets ESP-IDF's default */
#ifndef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS
#define CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS 200
#endif
