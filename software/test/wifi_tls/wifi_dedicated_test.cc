/*
 * GET_RANDOM through wifi_dedicated_call against M1's wifi_get_random.
 *
 * Both run in the same scripted world, seed by seed: replies that are right,
 * late, foreign, refused, short, stale from before a pool reset, bursts that
 * overflow the queue, failed buffer requests and transmits, preemption, a
 * tick counter about to wrap, a second caller holding the channel, and no
 * module. They must make the same calls in the same order, print the same
 * lines, and leave the same result, bytes, source, sequence number, flag and
 * queue behind.
 */
#include <string.h>
#include "world.h"
#include "wifi_random.h"
#include "check.h"
#undef printf

int m1_wifi_get_random(uint8_t *buf, uint16_t len, uint8_t *source);

// Answers to GET_RANDOM, and the ways they go wrong.
static void random_maker(command_buf_t *rx, const uint8_t *req, int req_size, int kind)
{
    const rpc_get_random_req *request = (const rpc_get_random_req *)req;
    uint16_t sequence = (req_size >= 0) ? request->hdr.sequence : (uint16_t)world_rand(65536);
    uint16_t len = (req_size >= 0) ? request->length : 32;
    if (len > RANDOM_MAX_BYTES) {
        len = RANDOM_MAX_BYTES;
    }
    rpc_get_random_resp *r = (rpc_get_random_resp *)rx->data;
    memset(rx->data, 0, sizeof(rx->data));
    r->hdr.command = CMD_GET_RANDOM;
    r->hdr.thread = WIFI_DEDICATED_THREAD;
    r->hdr.sequence = sequence;
    r->esp_err = 0;
    r->source = ENTROPY_RADIO;
    r->length = len;
    for (int i = 0; i < len; i++) {
        r->data[i] = (uint8_t)world_rand(256);
    }
    rx->size = sizeof(rpc_get_random_resp) + len;
    switch (kind) {
        case 4: r->hdr.sequence = sequence - 1; break; // late, for the previous request
        case 5: r->hdr.command = (uint8_t)(CMD_GET_RANDOM + 1 + world_rand(255)); break;
        case 6: r->esp_err = 0x103; r->length = 0; rx->size = sizeof(rpc_get_random_resp); break;
        case 7: r->source = ENTROPY_NONE; break;
        case 8: rx->size = world_rand(sizeof(rpc_get_random_resp) + len); break;
        case 9: r->length = len + 1; break;
        default: break; // 0-3: the answer
    }
}

typedef int (*get_random_t)(uint8_t *buf, uint16_t len, uint8_t *source);

typedef struct {
    std::string trace;
    int result;
    uint8_t buf[RANDOM_MAX_BYTES + 8];
    uint8_t source;
    uint16_t sequence_nr;
    bool waiting;
    size_t queued;
    int suspended;
} outcome_t;

static const uint16_t lengths[] = { 1, 2, 3, 31, 32, 255, 256, 257, 300, 511, 512 };

static void run(get_random_t impl, uint32_t seed, outcome_t *o)
{
    world_reset(seed, random_maker, false);
    uint16_t len = (world_rand(4) == 0) ? (uint16_t)(1 + world_rand(RANDOM_MAX_BYTES))
                                        : lengths[world_rand(sizeof(lengths) / sizeof(lengths[0]))];
    memset(o->buf, 0xEE, sizeof(o->buf));
    o->source = 0x55;
    o->result = impl(o->buf, len, &o->source);
    o->trace = world_trace;
    o->sequence_nr = sequence_nr;
    o->waiting = dedicated_waiting;
    o->queued = world_queued();
    o->suspended = world_suspended;
}

static void first_difference(const std::string &a, const std::string &b)
{
    size_t i = 0;
    while ((i < a.size()) && (i < b.size()) && (a[i] == b[i])) {
        i++;
    }
    size_t from = (i > 200) ? (i - 200) : 0;
    printf("        M1 : ...%s\n", a.substr(from, 300).c_str());
    printf("        new: ...%s\n", b.substr(from, 300).c_str());
}

void test_dedicated(void)
{
    printf("GET_RANDOM through wifi_dedicated_call, against M1, seed by seed\n");
    const uint32_t seeds = 200000;
    int differ = 0;
    int results[8] = { 0 };
    int with[8] = { 0 };
    const char *features[8] = { "a stale generation dropped", "the queue overflowing", "a reply refused or invalid",
                                "no reply at all", "no buffer", "a failed transmit", "a foreign reply skipped",
                                "the tail releasing replies" };
    static outcome_t m1, now;
    for (uint32_t seed = 1; seed <= seeds; seed++) {
        run(m1_wifi_get_random, seed, &m1);
        run(wifi_get_random, seed, &now);
        bool same = (m1.trace == now.trace) && (m1.result == now.result) &&
                    (memcmp(m1.buf, now.buf, sizeof(m1.buf)) == 0) && (m1.source == now.source) &&
                    (m1.sequence_nr == now.sequence_nr) && (m1.waiting == now.waiting) &&
                    (m1.queued == now.queued) && (m1.suspended == now.suspended);
        if (!same) {
            if (differ++ < 3) {
                printf("  seed %u differs: result %d vs %d\n", seed, m1.result, now.result);
                first_difference(m1.trace, now.trace);
            }
            continue;
        }
        results[(now.result >= 0 && now.result < 8) ? now.result : 7]++;
        const std::string &t = now.trace;
        with[0] += t.find("suspend\nresume\n") != std::string::npos; // taken without a free
        with[1] += t.find("(full)") != std::string::npos;
        with[2] += t.find("Get Random failed") != std::string::npos;
        with[3] += t.find("Get Random: no reply") != std::string::npos;
        with[4] += t.find("getbuffer 4 -> none") != std::string::npos;
        with[5] += t.find("-> failed") != std::string::npos;
        with[6] += (now.result == 0) && (t.find("isr queue") != t.rfind("isr queue"));
        with[7] += t.find("receive 0 -> b") != std::string::npos;
    }
    check(differ == 0, "%u seeds, M1 and the new code make the same calls and leave the same state (%d differ)",
          seeds, differ);
    printf("        results: 0 OK %d, 1 BUSY %d, 2 REFUSED %d, 3 INVALID %d, 4 NO_MODULE %d\n",
           results[0], results[1], results[2], results[3], results[4]);
    for (int i = 0; i < 8; i++) {
        check(with[i] > 100, "the seeds include %s (%d)", features[i], with[i]);
    }

    // What the split must not change for anyone: the channel is free again
    // and the queue empty after every call, and every take ran suspended.
    int left_over = 0;
    for (uint32_t seed = 1; seed <= 20000; seed++) {
        run(wifi_get_random, seed, &now);
        bool claimed = now.trace.find("getbuffer") != std::string::npos;
        if ((now.suspended != 0) || (claimed && (now.waiting || (now.queued != 0))) ||
            (now.trace.find("not suspended") != std::string::npos)) {
            left_over++;
        }
    }
    check(left_over == 0, "every call leaves the channel free, the queue empty and frees only while suspended (%d not)",
          left_over);
}
