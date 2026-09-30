/*
 * tls_group_cache.h
 *
 * Per-host memory of the key-exchange group a server asked for in a HelloRetryRequest (RAM only).
 * mbedTLS sends one key share, for the first group offered; after an HRR the group the server chose
 * is offered first for that host, so the next handshake needs no HRR.
 * - Only a session verified against the certificate bundle uses or teaches it
 *   (tls_group_session_tag): a pinned key or a custom CA does not authenticate a host name the way
 *   the bundle does, so those sessions must stay out. It learns only from a completed handshake: the
 *   HRR and the ServerHello are in the transcript the server's Finished authenticates.
 * - Entries are keyed by a 64-bit tag of the normalised host name under a secret drawn at the first
 *   use, so no one can choose another name that lands on the same entry.
 * - After every TLS_GROUP_REPROBE - 1 completed handshakes that used the learned group, the next one
 *   offers the default order again (a probe). A probe that completes without an HRR drops the entry,
 *   one that gets an HRR keeps it, and one that does not complete drops it too: an on-path attacker
 *   who blocks the probes then only returns the host to the default order.
 */

#ifndef TLS_GROUP_CACHE_H_
#define TLS_GROUP_CACHE_H_

#include <stdint.h>
#include <string.h>
#include "psa/crypto.h"

#define TLS_GROUP_CACHE    8
#define TLS_GROUP_REPROBE  8
#define TLS_GROUP_NAME_MAX 253

typedef struct {
    uint64_t tag;  // 0: free
    uint16_t group;
    uint8_t uses;  // completed handshakes that used the learned group since it was (re)learned
} tls_group_entry_t;

static tls_group_entry_t tls_group_table[TLS_GROUP_CACHE];
static uint8_t tls_group_next;
static uint8_t tls_group_secret[16];
static uint8_t tls_group_secret_set;

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

// The tag a session uses, or 0 when it must neither use nor teach the table
static inline uint64_t tls_group_session_tag(int verify, int cas, int cas_bundle, const char *name, int len)
{
    return (verify && (cas == cas_bundle) && (len > 0)) ? tls_group_tag(name, len) : 0;
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

// Fills out[] (room for nbase + 1) with base[], the learned group first if base[] has it, and a 0
// terminator. *probe is set when the entry exists and this offer is its default-order probe.
// Returns 1 when the offer is the default order.
static inline int tls_group_offer(uint64_t tag, const uint16_t *base, int nbase, uint16_t *out, int *probe)
{
    tls_group_entry_t *e = tls_group_find(tag);
    uint16_t first = 0;
    *probe = 0;
    if (e && (((e->uses + 1) % TLS_GROUP_REPROBE) == 0)) {
        *probe = 1;
    } else if (e) {
        for (int i = 0; i < nbase; i++) {
            if (base[i] == e->group) {
                first = e->group; // only a group this image offers: out[] then stays in bounds
            }
        }
    }
    int n = 0;
    if (first) {
        out[n++] = first;
    }
    for (int i = 0; i < nbase; i++) {
        if (base[i] != first) {
            out[n++] = base[i];
        }
    }
    out[n] = 0;
    return first == 0;
}

static inline void tls_group_forget(uint64_t tag)
{
    tls_group_entry_t *e = tls_group_find(tag);
    if (e) {
        memset(e, 0, sizeof(*e));
    }
}

// After a completed handshake of a session with a tag: an HRR to 'chosen' (re)learns it; no HRR on the
// default order drops the entry; no HRR on the learned group counts one use toward the next probe.
static inline void tls_group_learn(uint64_t tag, int saw_hrr, uint16_t chosen, int offered_default)
{
    if (!tag) {
        return;
    }
    tls_group_entry_t *e = tls_group_find(tag);
    if (saw_hrr && chosen) {
        for (int i = 0; !e && (i < TLS_GROUP_CACHE); i++) {
            if (tls_group_table[i].tag == 0) {
                e = &tls_group_table[i]; // a free slot before evicting a live entry
            }
        }
        if (!e) {
            e = &tls_group_table[tls_group_next];
            tls_group_next = (tls_group_next + 1) % TLS_GROUP_CACHE;
        }
        e->tag = tag;
        e->group = chosen;
        e->uses = 0;
    } else if (e && offered_default) {
        memset(e, 0, sizeof(*e));
    } else if (e) {
        e->uses++;
    }
}

#endif /* TLS_GROUP_CACHE_H_ */
