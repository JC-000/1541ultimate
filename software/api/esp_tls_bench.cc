// Temporary hardware benchmark. Fixed local peer; this file must never ship in a production firmware image.
//
// The same REST endpoint, parameters and JSON as software/api/tls_bench.cc (the Nios mbedTLS fixture), but the TLS
// session is the ESP32 offload's: every step goes through the firmware's own command target (network_target.cc and
// network_target_tls.cc), called as parse_command() with the same command bytes a C64 sends over the UCI, minus the UCI.
// So the consumer is a Nios task, as in the fixture, and the C64 is not involved.
#include "routes.h"

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "network_target.h"
#include "tls_bench_ca.h"
#include "esp_tls_bench_reply.h"

#include <stdio.h>
#include <string.h>

extern NetworkTarget net; // network_target.cc

// READ_CHUNK is the buffer of the fixture's loop (buffer[1024]); the checks run on a buffer of that size.
enum { BENCH_BYTES = 256 * 1024, BENCH_PORT = 18443, PLAIN_PORT = 18444, READ_CHUNK = 1024, BENCH_STACK_WORDS = 4096, DEADLINE_S = 180 };
// The host that runs the two peer servers (server.py :18443, plain_server.py :18444). Set it before building.
#define BENCH_PEER "192.0.2.10"
#define BENCH_NAME "bench.local"

struct BenchResult {
    int error;
    int verify_flags;
    uint32_t tcp_ms;
    uint32_t setup_ms;
    uint32_t handshake_ms;
    uint32_t transfer_ms;
    uint32_t bytes;
    uint32_t plain_tcp_ms;
    uint32_t plain_transfer_ms;
    uint32_t plain_bytes;
    uint32_t heap_before;
    uint32_t heap_after;
    uint32_t global_min_heap;
    uint32_t stack_free_words;
    uint32_t open_total_ms;
    uint32_t stats_rpc_ms;
    uint32_t tls_version;
    uint32_t tls_suite;
    uint32_t tls_group;
    char status[48]; // the text of the last non-OK status
};

static BenchResult result;
static volatile int bench_state; // 0 idle, 1 running, 2 complete

static uint32_t elapsed(TickType_t started)
{
    return (xTaskGetTickCount() - started) * portTICK_PERIOD_MS;
}

// One command through the target, as the command interface would hand it over, with a multi-block reply gathered
// (esp_tls_bench_reply.h). The reply bytes are left in reply_buf[0..reply_len). Returns the status code number (the
// "NN" of "NN,TEXT") of the block that ended the reply, and keeps the text of a non-OK one.
static uint8_t reply_buf[2 + READ_CHUNK + 16];
static int reply_len;

static int send_command(uint8_t *bytes, int length, BenchResult *metrics)
{
    Message command;
    command.message = bytes;
    command.length = length;
    command.last_part = true;
    Message *status;
    if (gather_reply(net, &command, &status, reply_buf, sizeof(reply_buf), &reply_len) < 0) {
        return 98;
    }
    if (!status || status->length < 2) {
        return 99;
    }
    int code = (status->message[0] - '0') * 10 + (status->message[1] - '0');
    if (code) {
        int n = status->length < (int)sizeof(metrics->status) - 1 ? status->length : (int)sizeof(metrics->status) - 1;
        memcpy(metrics->status, status->message, n);
        metrics->status[n] = 0;
    }
    return code;
}

static int run_plain(BenchResult *metrics)
{
    int socket = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) return -109;
    struct timeval timeout = {180, 0};
    lwip_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    lwip_setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = PP_HTONS(PLAIN_PORT);
    address.sin_addr.s_addr = inet_addr(BENCH_PEER);
    TickType_t started = xTaskGetTickCount();
    int error = 0;
    if (lwip_connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        error = -110;
        goto done;
    }
    metrics->plain_tcp_ms = elapsed(started);
    if (lwip_send(socket, "B", 1, 0) != 1) {
        error = -111;
        goto done;
    }
    started = xTaskGetTickCount();
    while (metrics->plain_bytes < BENCH_BYTES) {
        unsigned char buffer[1024];
        int n = lwip_recv(socket, buffer, sizeof(buffer), 0);
        if (n <= 0) { error = -112; goto done; }
        if (metrics->plain_bytes + (uint32_t)n > BENCH_BYTES) {
            error = -113;
            goto done;
        }
        for (int i = 0; i < n; ++i) {
            if (buffer[i] != (unsigned char)((metrics->plain_bytes + i) & 255)) {
                error = -114;
                goto done;
            }
        }
        metrics->plain_bytes += (uint32_t)n;
    }
    metrics->plain_transfer_ms = elapsed(started);
done:
    lwip_close(socket);
    return error;
}

// The payload of the READ reply in reply_buf (header, then the bytes), copied into buffer[]. -1 if the header and
// the bytes disagree.
static int read_payload(uint8_t *buffer)
{
    if (reply_len < 2) return -1;
    int total = reply_buf[0] | (reply_buf[1] << 8);
    if (total == 0xFFFF || total != reply_len - 2 || total > READ_CHUNK) return -1;
    memcpy(buffer, &reply_buf[2], total);
    return total;
}

static void run_benchmark(void)
{
    BenchResult metrics = {};
    metrics.heap_before = xPortGetFreeHeapSize();
    metrics.error = -1;
    int handle = -1;
    uint8_t command[2 + 2 + 2 + 32];
    uint8_t buffer[READ_CHUNK];

    // The CA the way a C64 installs it (one TRUST_CA command, the DER in one chunk), every run and untimed: the
    // target's and the module's copy do not survive a C64 reset or a module restart.
    {
        static uint8_t ca_command[6 + sizeof(tls_bench_ca_der)];
        ca_command[0] = 3; ca_command[1] = NET_CMD_TLS_TRUST_CA;
        ca_command[2] = 0; ca_command[3] = 0;
        ca_command[4] = sizeof(tls_bench_ca_der) & 0xFF; ca_command[5] = sizeof(tls_bench_ca_der) >> 8;
        memcpy(&ca_command[6], tls_bench_ca_der, sizeof(tls_bench_ca_der));
        if (send_command(ca_command, sizeof(ca_command), &metrics) != 0) {
            metrics.error = -100;
            goto done;
        }
    }

    {   // One global STATS round trip ($23 $FF: wifi_tls_stats on the module), timed on its own, outside the handshake.
        TickType_t started = xTaskGetTickCount();
        command[0] = 3; command[1] = NET_CMD_TLS_INFO; command[2] = 0xFF;
        int code = send_command(command, 3, &metrics);
        metrics.stats_rpc_ms = elapsed(started);
        if (code != 0) {
            metrics.error = -101;
            goto done;
        }
    }

    {   // OPEN_TLS: module OPEN RPC, name resolution (an IPv4 literal), TCP connect, handshake, STATS RPC, reply.
        static uint8_t open_command[6 + sizeof(BENCH_PEER) + sizeof(BENCH_NAME)];
        int n = 0;
        open_command[n++] = 3; open_command[n++] = NET_CMD_OPEN_TLS;
        open_command[n++] = BENCH_PORT & 0xFF; open_command[n++] = BENCH_PORT >> 8;
        open_command[n++] = 1; // CUSTOM CA
        open_command[n++] = 0; // flags
        memcpy(&open_command[n], BENCH_PEER, sizeof(BENCH_PEER) - 1); n += sizeof(BENCH_PEER) - 1;
        open_command[n++] = 0;
        memcpy(&open_command[n], BENCH_NAME, sizeof(BENCH_NAME) - 1); n += sizeof(BENCH_NAME) - 1;
        TickType_t started = xTaskGetTickCount();
        int code = send_command(open_command, n, &metrics);
        metrics.open_total_ms = elapsed(started);
        if (code != 0 || reply_len != 8) {
            metrics.error = -102;
            goto done;
        }
        handle = reply_buf[0];
        metrics.tls_version = reply_buf[1] | (reply_buf[2] << 8);
        metrics.tls_suite = reply_buf[3] | (reply_buf[4] << 8);
        metrics.tls_group = reply_buf[5] | (reply_buf[6] << 8);
    }

    {   // INFO: the handshake window the target measured itself (tls_handshake, network_target_tls.cc), read back.
        command[0] = 3; command[1] = NET_CMD_TLS_INFO; command[2] = (uint8_t)handle;
        if (send_command(command, 3, &metrics) != 0 || reply_len != 48) {
            metrics.error = -103;
            goto done;
        }
        metrics.handshake_ms = reply_buf[40] | (reply_buf[41] << 8) | (reply_buf[42] << 16) |
                               ((uint32_t)reply_buf[43] << 24);
        // Everything in OPEN_TLS that is not the handshake window: module OPEN RPC, resolve, socket, TCP connect.
        metrics.tcp_ms = metrics.open_total_ms > metrics.handshake_ms ? metrics.open_total_ms - metrics.handshake_ms : 0;
        metrics.setup_ms = 0; // no per-run setup of the fixture's kind (CA parse, DRBG seed, config): see tcp_ms
        metrics.verify_flags = 0; // a failed verification is a refused OPEN above
    }

    // The comparison is only valid for TLS 1.2 ECDHE-ECDSA CHACHA20-POLY1305 over secp256r1, the fixture's session.
    if (metrics.tls_version != 0x0303 || metrics.tls_suite != 0xCCA9 || metrics.tls_group != 0x0017) {
        metrics.error = -117;
        goto done;
    }

    {
        command[0] = 3; command[1] = NET_CMD_WRITE_SOCKET; command[2] = (uint8_t)handle; command[3] = 'B';
        if (send_command(command, 4, &metrics) != 0 || reply_len != 2 ||
            (reply_buf[0] | (reply_buf[1] << 8)) != 1) {
            metrics.error = -104;
            goto done;
        }
        TickType_t started = xTaskGetTickCount();
        while (metrics.bytes < BENCH_BYTES) {
            if (elapsed(started) > DEADLINE_S * 1000u) { metrics.error = -115; goto done; }
            command[0] = 3; command[1] = NET_CMD_READ_SOCKET; command[2] = (uint8_t)handle;
            command[3] = READ_CHUNK & 0xFF; command[4] = READ_CHUNK >> 8;
            int code = send_command(command, 5, &metrics);
            if (code == 2) continue; // NO DATA: the same wait as the fixture's blocking lwip_recv
            if (code != 0) { metrics.error = -105; if (code == 1 || code == 5) handle = -1; goto done; } // 01/05: the handle is gone
            int n = read_payload(buffer);
            if (n <= 0) { metrics.error = -105; goto done; }
            if (metrics.bytes + (uint32_t)n > BENCH_BYTES) {
                metrics.error = -106;
                goto done;
            }
            for (int i = 0; i < n; ++i) {
                if (buffer[i] != (unsigned char)((metrics.bytes + i) & 255)) {
                    metrics.error = -107;
                    goto done;
                }
            }
            metrics.bytes += (uint32_t)n;
        }
        metrics.transfer_ms = elapsed(started);
        // The end of the stream must be the peer's close_notify: "01,CONNECTION CLOSED BY HOST", and the handle is gone.
        started = xTaskGetTickCount();
        for (;;) {
            if (elapsed(started) > DEADLINE_S * 1000u) { metrics.error = -116; goto done; }
            command[0] = 3; command[1] = NET_CMD_READ_SOCKET; command[2] = (uint8_t)handle;
            command[3] = READ_CHUNK & 0xFF; command[4] = READ_CHUNK >> 8;
            int code = send_command(command, 5, &metrics);
            if (code == 2) continue;
            if (code != 1) { metrics.error = -108; goto done; }
            handle = -1;
            break;
        }
    }
    metrics.status[0] = 0;
    metrics.error = run_plain(&metrics);

done:
    if (handle >= 0) {
        command[0] = 3; command[1] = NET_CMD_CLOSE_SOCKET; command[2] = (uint8_t)handle;
        BenchResult scratch = {};
        send_command(command, 3, &scratch);
    }
    metrics.heap_after = xPortGetFreeHeapSize();
    metrics.global_min_heap = xPortGetMinimumEverFreeHeapSize();
    metrics.stack_free_words = uxTaskGetStackHighWaterMark(NULL);
    result = metrics;
    taskENTER_CRITICAL();
    bench_state = 2;
    taskEXIT_CRITICAL();
    printf("ESPTLSBENCH error=%d status=%s tcp=%lu handshake=%lu transfer=%lu bytes=%lu plain=%lu/%lu open=%lu heap=%lu/%lu min=%lu stack=%lu\n",
           result.error, result.status, (unsigned long)result.tcp_ms, (unsigned long)result.handshake_ms,
           (unsigned long)result.transfer_ms, (unsigned long)result.bytes, (unsigned long)result.plain_transfer_ms,
           (unsigned long)result.plain_bytes, (unsigned long)result.open_total_ms, (unsigned long)result.heap_before,
           (unsigned long)result.heap_after, (unsigned long)result.global_min_heap, (unsigned long)result.stack_free_words);
}

static void bench_task(void *)
{
    run_benchmark();
    vTaskDelete(NULL);
}

API_CALL(PUT, machine, tls_bench, NULL, ARRAY( { }))
{
    taskENTER_CRITICAL();
    bool busy = bench_state == 1;
    if (!busy) bench_state = 1;
    taskEXIT_CRITICAL();
    if (!busy && xTaskCreate(bench_task, "ESP TLS Bench", BENCH_STACK_WORDS,
                             NULL, PRIO_HW_SERVICE, NULL) != pdPASS) {
        bench_state = 0;
        resp->json->add("state", "task_create_failed");
    } else {
        resp->json->add("state", busy ? "busy" : "running");
    }
    resp->json_response(HTTP_OK);
}

API_CALL(GET, machine, tls_bench, NULL, ARRAY( { }))
{
    int state = bench_state;
    resp->json->add("state", state == 2 ? "complete" : state == 1 ? "running" : "idle");
    if (state == 2) {
        resp->json->add("error", result.error);
        resp->json->add("verify_flags", result.verify_flags);
        resp->json->add("tcp_ms", (int)result.tcp_ms);
        resp->json->add("setup_ms", (int)result.setup_ms);
        resp->json->add("handshake_ms", (int)result.handshake_ms);
        resp->json->add("transfer_ms", (int)result.transfer_ms);
        resp->json->add("bytes", (int)result.bytes);
        resp->json->add("plain_tcp_ms", (int)result.plain_tcp_ms);
        resp->json->add("plain_transfer_ms", (int)result.plain_transfer_ms);
        resp->json->add("plain_bytes", (int)result.plain_bytes);
        resp->json->add("heap_before", (int)result.heap_before);
        resp->json->add("heap_after", (int)result.heap_after);
        resp->json->add("global_min_heap", (int)result.global_min_heap);
        resp->json->add("stack_free_words", (int)result.stack_free_words);
        resp->json->add("open_total_ms", (int)result.open_total_ms);
        resp->json->add("stats_rpc_ms", (int)result.stats_rpc_ms);
        resp->json->add("tls_version", (int)result.tls_version);
        resp->json->add("tls_suite", (int)result.tls_suite);
        resp->json->add("tls_group", (int)result.tls_group);
        resp->json->add("status", result.status);
        resp->json->add("entropy", "ESP32 hardware RNG (Wi-Fi radio on)");
        resp->json->add("tls", "ESP32 offload (module TLS), session checked 1.2 ECDHE-ECDSA CHACHA20-POLY1305 secp256r1");
        resp->json->add("time", "SNTP UTC");
        resp->json->add("client", "Nios II/f, FreeRTOS task, NetworkTarget commands (ESP32 offload)");
    }
    resp->json_response(HTTP_OK);
}
