/* Host stand-ins for the ESP-IDF v5.3.1 declarations tls_engine.c and rpc_dispatch.c use. Types and
   signatures copied from the v5.3.1 headers where the TLS spike code calls them. */
#ifndef ESP_STUB_ALL_H
#define ESP_STUB_ALL_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_NOT_SUPPORTED 0x106
#define ESP_ERR_TIMEOUT 0x107
typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef uint32_t TickType_t;
typedef void *QueueHandle_t;
typedef void *SemaphoreHandle_t;
typedef void *TaskHandle_t;
#define pdFALSE 0
#define pdTRUE 1
#define portTICK_PERIOD_MS 1
#define tskIDLE_PRIORITY 0
BaseType_t xQueueSend(QueueHandle_t q, const void *item, TickType_t t);
BaseType_t xQueueReceive(QueueHandle_t q, void *item, TickType_t t);
QueueHandle_t xQueueCreate(UBaseType_t n, UBaseType_t size);
BaseType_t xSemaphoreGive(SemaphoreHandle_t s);
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, uint32_t stack, void *arg, UBaseType_t prio, TaskHandle_t *h);
void vTaskDelay(TickType_t t);
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t t);
#define ESP_LOGI(tag, fmt, ...) printf("I %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) printf("W %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) printf("E %s: " fmt "\n", tag, ##__VA_ARGS__)
int64_t esp_timer_get_time(void);
#define MALLOC_CAP_8BIT (1<<2)
#define MALLOC_CAP_INTERNAL (1<<11)
size_t heap_caps_get_free_size(uint32_t caps);
size_t heap_caps_get_minimum_free_size(uint32_t caps);
size_t heap_caps_get_largest_free_block(uint32_t caps);
esp_err_t heap_caps_monitor_local_minimum_free_size_start(void);
esp_err_t heap_caps_monitor_local_minimum_free_size_stop(void);
void esp_fill_random(void *buf, size_t len);
typedef enum { WIFI_IF_STA = 0 } wifi_interface_t;
esp_err_t esp_wifi_get_mac(wifi_interface_t ifx, uint8_t mac[6]);
esp_err_t esp_wifi_disconnect(void);
#define UART_NUM_1 1
#define UART_HW_FLOWCTRL_CTS_RTS 3
#define UART_HW_FLOWCTRL_DISABLE 0
esp_err_t uart_set_baudrate(int n, uint32_t b);
esp_err_t uart_set_hw_flow_ctrl(int n, int f, uint8_t t);
esp_err_t uart_set_line_inverse(int n, uint32_t m);
esp_err_t gpio_set_level(int g, uint32_t l);
typedef struct esp_netif_obj esp_netif_t;
typedef int8_t err_t;
esp_err_t esp_netif_transmit(esp_netif_t *n, void *data, size_t len);
typedef uint16_t u16_t;
#endif
