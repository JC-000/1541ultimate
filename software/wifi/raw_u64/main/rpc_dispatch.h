/*
 * rpc_dispatch.h
 *
 *  Created on: Nov 10, 2021
 *      Author: gideon
 */

#ifndef SOFTWARE_WIFI_SCAN_MAIN_RPC_DISPATCH_H_
#define SOFTWARE_WIFI_SCAN_MAIN_RPC_DISPATCH_H_

#ifndef RECOVERYAPP
    #include "freertos/FreeRTOS.h"
    #include "freertos/queue.h"
    #include "freertos/task.h"
#endif
#include "cmd_buffer.h" // For the constant NUM_BUFFERS

typedef struct {
    TaskHandle_t task;
    QueueHandle_t queue;
} dispatcher_t;

void create_dispatchers(int stacksize, command_buf_context_t *bufs);
void dispatch(void *ct);
void start_dispatch(QueueHandle_t queue);
void send_button_event(uint8_t button);
void send_keepalive();

#define IDENT_STRING "ESP32 WiFi Bridge V1.303"
#define IDENT_MAJOR   1
// 1.6: the connector retries after a dropped link instead of idling in
// Disconnected forever. The Ultimate's updater only reflashes the module
// when this differs from what the module reports, so a module change that
// does not bump it is silently never installed.
// 1.100 (dev builds, 1.7 when released): CMD_GET_RANDOM.
// 1.200 (dev builds of the TLS spike): CMD_TLS_OPEN/STEP/CLOSE/STATS.
// 1.201 (dev): a TLS 1.3 NewSessionTicket never fails the session.
// 1.202 (dev): any number of tickets ahead of a reply; tickets signalled on every mbedTLS.
// 1.203 (dev): an empty application data record no longer closes the session.
// 1.301 (dev builds on ESP-IDF 6.0.3 / mbedTLS 4.1.1): the bridge ported to ESP-IDF 6.
// 1.302 (dev): the mbedTLS 4 engine; PSA key store locked (MBEDTLS_THREADING_C); ESP-IDF 6 defaults taken.
// 1.303 (dev): MBEDTLS_ECP_FIXED_POINT_OPTIM back on (the 5.3.1 value) until handshakes are timed on the rig.
#define IDENT_MINOR   303
#define MULTITHREADED 0
#define DISPATCHER_STACK 8192 // was 3072: the TLS handshake runs on this task

#endif /* SOFTWARE_WIFI_SCAN_MAIN_RPC_DISPATCH_H_ */
