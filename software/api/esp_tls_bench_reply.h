// Temporary hardware benchmark helper (bench only). One command through a NetworkTarget, the way the command
// interface takes it: parse_command, then get_more_data while the reply says more is coming (Data More). Every block
// is appended to out[], so a READ reply comes back as its 2-byte header followed by the whole payload. *status is the
// status of the block that ended the reply (intermediate blocks carry none). Kept apart so a host build can test it.
#ifndef ESP_TLS_BENCH_REPLY_H
#define ESP_TLS_BENCH_REPLY_H

#include <string.h>

// 0 on success; -1 if the reply does not fit out[] or never ends.
template <class Target>
static int gather_reply(Target &target, Message *command, Message **status, uint8_t *out, int room, int *length)
{
    Message *reply = NULL;
    *status = NULL;
    *length = 0;
    target.parse_command(command, &reply, status);
    for (int blocks = 0; reply && blocks < 16; blocks++) {
        if (*length + reply->length > room) {
            return -1;
        }
        memcpy(out + *length, reply->message, reply->length);
        *length += reply->length;
        if (reply->last_part) {
            return 0;
        }
        target.get_more_data(&reply, status);
    }
    return reply ? -1 : 0;
}

#endif
