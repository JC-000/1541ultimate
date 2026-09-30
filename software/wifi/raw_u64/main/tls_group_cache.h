/*
 * tls_group_cache.h
 *
 * Per-host memory of the key-exchange group a server asked for in a HelloRetryRequest (RAM only).
 * mbedTLS sends one key share, for the first group offered; after an HRR the group the server chose
 * is offered first for that host, so the next handshake needs no HRR.
 * - Only a completed handshake that verified the server against the certificate bundle teaches it
 *   (tls_group_may_learn): the HRR and the ServerHello are in the transcript the server's Finished
 *   authenticates, and the host name is the one the certificate was checked against.
 * - Entries are keyed by a 64-bit tag of the normalised host name under a secret drawn at the first
 *   use, so no one can choose another name that lands on the same entry.
 * - Every TLS_GROUP_REPROBE-th use offers the default order again: a server that now takes the
 *   default group without an HRR drops the entry, one that still asks for another group keeps it.
 */

#ifndef TLS_GROUP_CACHE_H_
#define TLS_GROUP_CACHE_H_

#include <stdint.h>
#include <string.h>
#include "psa/crypto.h"

#define TLS_GROUP_CACHE   8
#define TLS_GROUP_REPROBE 8
#define TLS_GROUP_NAME_MAX 253

typedef struct {
    uint64_t tag; // 0: free
    uint16_t group;
    uint8_t uses;
} tls_group_entry_t;

static tls_group_entry_t tls_group_table[TLS_GROUP_CACHE];
static uint8_t tls_group_next;
static uint8_t tls_group_secret[16];
static uint8_t tls_group_secret_set;

// Only a session verified against the certificate bundle may teach the table
static inline int tls_group_may_learn(int verify, int cas, int cas_bundle)
{
    return verify && (cas == cas_bundle);
}

// The tag of a host name: SHA-256(secret || lower-case name without one trailing dot), first 8 bytes.
// Returns 0 (no caching) for an empty name or when PSA fails.
static inline uint64_t tls_group_tag(const char *name, int len)
{
    uint8_t buf[sizeof(tls_group_secret) + TLS_GROUP_NAME_MAX];
    uint8_t hash[32];
    size_t hash_len;
    if ((len > 0) && (name[len - 1] == '.')) {
        len--;
    }
    if ((len <= 0) || (len > TLS_GROUP_NAME_MAX)) {
        return 0;
    }
    if (!tls_group_secret_set) {
        if (psa_generate_random(tls_group_secret, sizeof(tls_group_secret)) != PSA_SUCCESS) {
            return 0;
        }
        tls_group_secret_set = 1;
    }
    memcpy(buf, tls_group_secret, sizeof(tls_group_secret));
    for (int i = 0; i < len; i++) {
        char c = name[i];
        buf[sizeof(tls_group_secret) + i] = (uint8_t)(((c >= 'A') && (c <= 'Z')) ? (c - 'A' + 'a') : c);
    }
    if (psa_hash_compute(PSA_ALG_SHA_256, buf, sizeof(tls_group_secret) + len, hash, sizeof(hash), &hash_len) !=
        PSA_SUCCESS) {
        return 0;
    }
    uint64_t tag = 0;
    for (int i = 0; i < 8; i++) {
        tag = (tag << 8) | hash[i];
    }
    return tag ? tag : 1;
}

static inline tls_group_entry_t *tls_group_find(uint64_t tag)
{
    for (int i = 0; tag && (i < TLS_GROUP_CACHE); i++) {
        if (tls_group_table[i].tag == tag) {
            return &tls_group_table[i];
        }
    }
    return NULL;
}

// The group to offer first for this host, or 0 for the default order (no entry, or a re-probe)
static inline uint16_t tls_group_first(uint64_t tag)
{
    tls_group_entry_t *e = tls_group_find(tag);
    if (!e) {
        return 0;
    }
    e->uses++;
    return (e->uses % TLS_GROUP_REPROBE) ? e->group : 0;
}

// After a completed handshake that may teach (tls_group_may_learn): an HRR to 'chosen' stores it;
// no HRR while the default order was offered means the entry is no longer needed.
static inline void tls_group_learn(uint64_t tag, int saw_hrr, uint16_t chosen, int offered_default)
{
    tls_group_entry_t *e = tls_group_find(tag);
    if (!tag) {
        return;
    }
    if (saw_hrr && chosen) {
        if (!e) {
            e = &tls_group_table[tls_group_next];
            tls_group_next = (tls_group_next + 1) % TLS_GROUP_CACHE;
        }
        e->tag = tag;
        e->group = chosen;
        e->uses = 0;
    } else if (!saw_hrr && offered_default && e) {
        memset(e, 0, sizeof(*e));
    }
}

#endif /* TLS_GROUP_CACHE_H_ */
