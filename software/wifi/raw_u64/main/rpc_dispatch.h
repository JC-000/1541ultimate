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
void dispatch_command(command_buf_t *buf);
void tls_serve(command_buf_t *buf);
void start_dispatch(QueueHandle_t queue);
void send_button_event(uint8_t button);
void send_keepalive();

#define IDENT_STRING "ESP32 WiFi Bridge V1.309"
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
// 1.304 (dev): the certificate bundle logs at the default level again.
// 1.305 (dev): CROSS_SIGNED_VERIFY pinned (not default-tracked); the engine refuses to build with =n.
// 1.306 (dev): M3 (M3-SPEC v1 section 5): sessions named by (slot, tag), trust modes BUNDLE/CUSTOM/PIN, TLS 1.2
//              fallback, failure reasons, NO_READ, CLOSE_ALL and SET_CA; TLS runs on its own task.
// 1.308 (dev): M3 integration: 1.305 + 1.306, and mbedTLS accepts a HelloRetryRequest cookie (a carried patch).
// 1.309 (dev): stock mbedTLS as ESP-IDF imports it (the cookie patch removed), and the certificate bundle from
//              the vendored Mozilla root store (software/wifi/ca_store) instead of ESP-IDF's.
#define IDENT_MINOR   309
#define MULTITHREADED 0
#define DISPATCHER_STACK 3072 // upstream's value: TLS runs on its own task
#define TLS_TASK_STACK   8192 // M3-SPEC 5.3: twice the dispatcher stack M2 measured in handshakes
#define TLS_QUEUE_DEPTH  2    // M3-SPEC 5.3: one request outstanding, and a CLOSE behind a step that timed out

#endif /* SOFTWARE_WIFI_SCAN_MAIN_RPC_DISPATCH_H_ */
