/*
 * tls_hello_scan.h
 *
 * Reads the key_share group out of a TLS 1.3 HelloRetryRequest and ServerHello as the server's
 * bytes pass through the recv callback. Nothing is decrypted or changed: the engine only uses the
 * result after mbedTLS has completed the handshake, when the transcript those two messages are part
 * of has been authenticated by the server's Finished.
 */

#ifndef TLS_HELLO_SCAN_H_
#define TLS_HELLO_SCAN_H_

#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t hdr[5];     // record header being collected
    uint8_t hdr_len;
    uint16_t rec_left;  // body bytes of the current record still to come
    uint8_t hello[128]; // start of the current handshake record: reaches key_share in both orders
    uint8_t hello_len;
    uint8_t done;       // a ServerHello (not an HRR) was seen, or something we don't parse
    uint8_t saw_hrr;
    uint16_t chosen;    // key_share group of the ServerHello, 0 if none
} tls_hello_scan_t;

// SHA-256("HelloRetryRequest"), the random of an HRR (RFC 8446 4.1.3)
static const uint8_t tls_hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

static inline void tls_hello_parse(tls_hello_scan_t *t)
{
    const uint8_t *h = t->hello;
    int n = t->hello_len;
    // handshake header 4, legacy_version 2, random 32, legacy_session_id_echo 1 + len
    if ((n < 39) || (h[0] != 2)) { // not a ServerHello: stop looking
        t->done = 1;
        return;
    }
    int hrr = (memcmp(h + 6, tls_hrr_random, sizeof(tls_hrr_random)) == 0);
    int off = 39 + h[38] + 2 + 1 + 2; // cipher_suite, compression, extensions length
    uint16_t group = 0;
    while (off + 4 <= n) {
        int type = (h[off] << 8) | h[off + 1];
        int len = (h[off + 2] << 8) | h[off + 3];
        if ((type == 0x0033) && (len >= 2) && (off + 6 <= n)) {
            group = (uint16_t)((h[off + 4] << 8) | h[off + 5]); // HRR: selected_group; ServerHello: KeyShareEntry.group
            break;
        }
        off += 4 + len;
    }
    if (hrr) {
        t->saw_hrr = 1;
    } else {
        t->chosen = group; // stays 0 for a TLS 1.2 ServerHello, which has no key_share
        t->done = 1;
    }
}

static inline void tls_hello_scan(tls_hello_scan_t *t, const uint8_t *p, size_t n)
{
    while (n && !t->done) {
        if (t->hdr_len < sizeof(t->hdr)) {
            t->hdr[t->hdr_len++] = *p++;
            n--;
            if (t->hdr_len == sizeof(t->hdr)) {
                t->rec_left = (uint16_t)((t->hdr[3] << 8) | t->hdr[4]);
                t->hello_len = 0;
                if (t->rec_left == 0) {
                    t->hdr_len = 0;
                }
            }
            continue;
        }
        size_t take = (n < t->rec_left) ? n : t->rec_left;
        if (t->hdr[0] == 22) { // handshake; ChangeCipherSpec (20) records are skipped
            size_t room = sizeof(t->hello) - t->hello_len;
            size_t copy = (take < room) ? take : room;
            memcpy(t->hello + t->hello_len, p, copy);
            t->hello_len += copy;
        } else if (t->hdr[0] != 20) { // encrypted or unexpected: nothing more to learn
            t->done = 1;
        }
        p += take;
        n -= take;
        t->rec_left -= take;
        if (t->rec_left == 0) {
            if (t->hdr[0] == 22) {
                tls_hello_parse(t);
            }
            t->hdr_len = 0;
        }
    }
}

#endif /* TLS_HELLO_SCAN_H_ */
