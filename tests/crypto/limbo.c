/*
 * x509-limbo harness for mbedTLS: validates a server's chain with the calls the TLS 1.3 client
 * makes in ssl_tls13_validate_certificate() (library/ssl_tls13_generic.c):
 * mbedtls_x509_crt_verify_with_profile() on the chain from the Certificate message, with the
 * default certificate profile, the host name and the configured verify callback, and then the
 * leaf's keyUsage (digitalSignature) and extendedKeyUsage (serverAuth). That function is static,
 * so this is a copy of its checks, not a call to it: the suite does not test the TLS layer (the
 * record layer, the handshake state machine, Finished, CertificateVerify, or that the TLS layer
 * passes the host name and runs these checks at all).
 *
 * tls_engine.c verifies in one of two ways, and each case says which:
 *   ca      the test CA as the CA chain, no verify callback, no CRL
 *   bundle  ESP-IDF's certificate bundle (esp_crt_bundle.c, built in from ESP_IDF_COMMIT): an
 *           empty CA chain and esp_crt_verify_callback(), with a bundle made from the case's
 *           trusted certificates the way gen_crt_bundle.py makes one
 *
 * The order of the intermediates matters: mbedTLS only looks for a parent further down the
 * presented list (x509_crt.c:2400) and does not go back. limbo gives its intermediates as a set,
 * so in "path" order the harness sends them the way a server does (RFC 8446 4.4.2): the leaf,
 * then each certificate's issuer on a path to a trusted certificate, then the rest. Where there
 * is more than one such path, each is tried, as a server could send any of them, and the chain is
 * accepted if one is; with none, the case's own order. "given" sends the case's own order only.
 *
 * One test case per line on stdin, certificates as DER in hex:
 *   <time, unix> <host name> <path|given> <ca|bundle> <none|leaf|issuer> <leaf> <n> <intermediate>...
 *   <m> <trusted>...
 * The fifth field flips the last byte (inside the signature) of the leaf, or of the leaf's issuer
 * on the first path; "issuer" answers "na 0" unless there is a path and no other certificate has
 * that issuer's name (another could stand in for it).
 * One result per line on stdout: "<ret> <verify flags in hex>", ret 0 when the chain is accepted.
 *
 *   limbo bundle <cert hex>...   prints the bundle those certificates make, in hex
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/md.h"
#include "esp_crt_bundle.h"

// esp_crt_bundle.c defines it without declaring it in its header
int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

#define MAX_CERTS 1024
#define MAX_PATHS 16

// mbedTLS reads the clock through time() (MBEDTLS_HAVE_TIME_DATE, mbedtls_time() is time());
// this definition in the executable answers with the test case's validation time.
static time_t validation_time;

time_t time(time_t *t)
{
    if (t) {
        *t = validation_time;
    }
    return validation_time;
}

// esp_crt_bundle.c falls back to a bundle linked into the image; there is none here
const uint8_t no_bundle[1] __asm__("_binary_x509_crt_bundle_start");
const uint8_t no_bundle_end[1] __asm__("_binary_x509_crt_bundle_end");

typedef struct {
    unsigned char *p;
    size_t len;
} der_t;

static der_t unhex(const char *s)
{
    der_t d = { NULL, strlen(s) / 2 };
    // Exactly as long as the data, so that a sanitizer build sees a read past its end
    d.p = malloc(d.len ? d.len : 1);
    for (size_t i = 0; i < d.len; i++) {
        unsigned int v;
        sscanf(s + 2 * i, "%2x", &v);
        d.p[i] = (unsigned char)v;
    }
    return d;
}

// Parses a certificate the way each side gets it: the peer's as ssl_tls13_parse_certificate()
// takes the Certificate message's entries (one that does not parse fails the handshake, except
// for an unknown signature algorithm, which is skipped), the trusted ones as tls_engine.c
// does (any certificate that does not parse fails the OPEN)
static int parse(mbedtls_x509_crt *chain, der_t d, int peer)
{
    int ret = mbedtls_x509_crt_parse_der(chain, d.p, d.len);
    if (peer && (ret == MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND)) {
        ret = 0;
    }
    return ret;
}

static int same(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
    return (a->len == b->len) && !memcmp(a->p, b->p, a->len);
}

// ---- server order --------------------------------------------------------------------------

typedef struct {
    mbedtls_x509_crt *c;           // the intermediates, then the leaf at [n]
    int n;
    const mbedtls_x509_crt *trusted;
    int used[MAX_CERTS];
    int path[MAX_CERTS];
    int paths[MAX_PATHS][MAX_CERTS + 1]; // each: its length, then the intermediates in order
    int count;
    int budget;                    // signature checks left: limbo has chains made to exhaust builders
} search_t;

// Whether parent issued child: the names chain and parent's key verifies child's signature.
// Private fields: only to order the chain; the verdict is mbedtls_x509_crt_verify_with_profile()'s
static int issued(search_t *s, const mbedtls_x509_crt *parent, const mbedtls_x509_crt *child)
{
    if ((--s->budget < 0) || !same(&parent->subject_raw, &child->issuer_raw)) {
        return 0;
    }
    mbedtls_md_type_t md_type = child->MBEDTLS_PRIVATE(sig_md);
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(md_type);
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    if ((md == NULL) || (mbedtls_md(md, child->tbs.p, child->tbs.len, hash) != 0)) {
        return 0;
    }
    return mbedtls_pk_verify_ext(child->MBEDTLS_PRIVATE(sig_pk), child->MBEDTLS_PRIVATE(sig_opts),
                                 (mbedtls_pk_context *)&parent->pk, md_type, hash, mbedtls_md_get_size(md),
                                 child->MBEDTLS_PRIVATE(sig).p, child->MBEDTLS_PRIVATE(sig).len) == 0;
}

// Records every path from c[cur] through unused intermediates to a trusted certificate
static void extend(search_t *s, int cur, int k)
{
    for (const mbedtls_x509_crt *t = s->trusted; t && t->raw.p; t = t->next) {
        if ((s->count < MAX_PATHS) && issued(s, t, &s->c[cur])) {
            s->paths[s->count][0] = k;
            memcpy(&s->paths[s->count][1], s->path, k * sizeof(int));
            s->count++;
            break;
        }
    }
    for (int i = 0; (i < s->n) && (s->count < MAX_PATHS); i++) {
        if (!s->used[i] && issued(s, &s->c[i], &s->c[cur])) {
            s->used[i] = 1;
            s->path[k] = i;
            extend(s, i, k + 1);
            s->used[i] = 0;
        }
    }
}

// The orders to try, each a full permutation of the intermediates: the paths found, each
// followed by the rest as given; or the case's own order when no path is found
static int server_orders(der_t leaf, der_t *inter, int n, const mbedtls_x509_crt *trusted,
                         int orders[][MAX_CERTS], int *alone)
{
    search_t *s = calloc(1, sizeof(*s));
    s->c = calloc(n + 1, sizeof(*s->c));
    s->n = n;
    s->trusted = trusted;
    s->budget = 20000;
    for (int i = 0; i <= n; i++) {
        mbedtls_x509_crt_init(&s->c[i]);
    }
    for (int i = 0; i < n; i++) {
        if (mbedtls_x509_crt_parse_der(&s->c[i], inter[i].p, inter[i].len) != 0) {
            s->used[i] = 1; // cannot say whose issuer it is: it goes with the rest
        }
    }
    if (mbedtls_x509_crt_parse_der(&s->c[n], leaf.p, leaf.len) == 0) {
        extend(s, n, 0);
    }
    int count = s->count ? s->count : 1;
    for (int p = 0; p < count; p++) {
        int k = 0;
        static int on[MAX_CERTS];
        memset(on, 0, sizeof(on));
        for (int j = 0; s->count && (j < s->paths[p][0]); j++) {
            orders[p][k++] = s->paths[p][1 + j];
            on[s->paths[p][1 + j]] = 1;
        }
        for (int i = 0; i < n; i++) {
            if (!on[i]) {
                orders[p][k++] = i;
            }
        }
    }
    // The leaf's issuer on the first path, if nothing else has its name
    *alone = s->count && (s->paths[0][0] > 0);
    int issuer = *alone ? s->paths[0][1] : 0;
    for (int i = 0; *alone && (i < n); i++) {
        *alone = (i == issuer) || !same(&s->c[i].subject_raw, &s->c[issuer].subject_raw);
    }
    for (const mbedtls_x509_crt *t = trusted; *alone && t && t->raw.p; t = t->next) {
        *alone = !same(&t->subject_raw, &s->c[issuer].subject_raw);
    }
    for (int i = 0; i <= n; i++) {
        mbedtls_x509_crt_free(&s->c[i]);
    }
    free(s->c);
    free(s);
    return count;
}

// ---- ESP-IDF certificate bundle ------------------------------------------------------------

// A bundle as gen_crt_bundle.py writes it: the number of certificates, then for each, sorted by
// subject name DER: name length, key length (16 bits each, big-endian), the subject name DER and
// the SubjectPublicKeyInfo DER
static int cmp_name(const void *a, const void *b)
{
    const mbedtls_x509_buf *x = &(*(mbedtls_x509_crt *const *)a)->subject_raw;
    const mbedtls_x509_buf *y = &(*(mbedtls_x509_crt *const *)b)->subject_raw;
    int r = memcmp(x->p, y->p, (x->len < y->len) ? x->len : y->len);
    return r ? r : (int)x->len - (int)y->len;
}

static unsigned char *make_bundle(mbedtls_x509_crt *list, size_t *size)
{
    static mbedtls_x509_crt *sorted[MAX_CERTS];
    int n = 0;
    *size = 2;
    for (mbedtls_x509_crt *c = list; c && c->raw.p && (n < MAX_CERTS); c = c->next) {
        sorted[n++] = c;
        *size += 4 + c->subject_raw.len + c->pk_raw.len;
    }
    qsort(sorted, n, sizeof(sorted[0]), cmp_name);
    unsigned char *b = malloc(*size), *p = b + 2;
    b[0] = (unsigned char)(n >> 8);
    b[1] = (unsigned char)n;
    for (int i = 0; i < n; i++) {
        size_t nl = sorted[i]->subject_raw.len, kl = sorted[i]->pk_raw.len;
        p[0] = (unsigned char)(nl >> 8);
        p[1] = (unsigned char)nl;
        p[2] = (unsigned char)(kl >> 8);
        p[3] = (unsigned char)kl;
        memcpy(p + 4, sorted[i]->subject_raw.p, nl);
        memcpy(p + 4 + nl, sorted[i]->pk_raw.p, kl);
        p += 4 + nl + kl;
    }
    return b;
}

// ---- one case ------------------------------------------------------------------------------

// The TLS 1.3 client's checks on one presented chain
static int verify(der_t leaf, der_t *inter, const int *order, int n, mbedtls_x509_crt *trusted, int bundle,
                  const char *host, uint32_t *flags)
{
    mbedtls_x509_crt chain, empty;
    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&empty);
    int ret = parse(&chain, leaf, 1);
    for (int i = 0; i < n; i++) {
        ret = ret ? ret : parse(&chain, inter[order[i]], 1);
    }
    *flags = 0;
    if ((ret == 0) && (chain.raw.p == NULL)) {
        ret = -2; // every entry skipped: the client has no peer certificate and aborts
    } else if (ret == 0) {
        char *name = strdup(host); // in a buffer of its own, as above
        ret = mbedtls_x509_crt_verify_with_profile(&chain, bundle ? &empty : trusted, NULL,
                                                   &mbedtls_x509_crt_profile_default, name, flags,
                                                   bundle ? esp_crt_verify_callback : NULL, NULL);
        free(name);
        if ((mbedtls_x509_crt_check_key_usage(&chain, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0) ||
            (mbedtls_x509_crt_check_extended_key_usage(&chain, MBEDTLS_OID_SERVER_AUTH,
                                                       MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0)) {
            ret = ret ? ret : -1; // MBEDTLS_ERR_SSL_BAD_CERTIFICATE in the TLS layer
        }
    }
    mbedtls_x509_crt_free(&chain);
    return ret;
}

static void run_line(char *line)
{
    static der_t inter[MAX_CERTS];
    static int orders[MAX_PATHS][MAX_CERTS];
    char *save;
    char *when = strtok_r(line, " \n", &save);
    char *host = strtok_r(NULL, " \n", &save);
    int given = !strcmp(strtok_r(NULL, " \n", &save), "given");
    int bundle = !strcmp(strtok_r(NULL, " \n", &save), "bundle");
    char *flip = strtok_r(NULL, " \n", &save);
    der_t leaf = unhex(strtok_r(NULL, " \n", &save));
    int n = atoi(strtok_r(NULL, " \n", &save));
    if ((n < 0) || (n > MAX_CERTS)) {
        fprintf(stderr, "%d intermediates, at most %d\n", n, MAX_CERTS);
        exit(2);
    }
    for (int i = 0; i < n; i++) {
        inter[i] = unhex(strtok_r(NULL, " \n", &save));
        orders[0][i] = i;
    }
    mbedtls_x509_crt trusted;
    mbedtls_x509_crt_init(&trusted);
    validation_time = (time_t)strtoll(when, NULL, 10);
    int ret = 0, m = atoi(strtok_r(NULL, " \n", &save));
    for (int i = 0; i < m; i++) {
        der_t d = unhex(strtok_r(NULL, " \n", &save));
        ret = ret ? ret : parse(&trusted, d, 0);
        free(d.p);
    }
    int count = 1, alone = 0;
    if (!given) {
        count = server_orders(leaf, inter, n, &trusted, orders, &alone);
    }
    int na = 0;
    if (!strcmp(flip, "leaf") && leaf.len) {
        leaf.p[leaf.len - 1] ^= 1;
    } else if (!strcmp(flip, "issuer") && alone) {
        inter[orders[0][0]].p[inter[orders[0][0]].len - 1] ^= 1;
    } else if (!strcmp(flip, "issuer")) {
        na = 1;
    }
    uint32_t flags = 0;
    unsigned char *b = NULL;
    size_t size = 0;
    if ((ret == 0) && bundle) {
        b = make_bundle(&trusted, &size);
        ret = esp_crt_bundle_set(b, size);
    }
    // Accepted if the client accepts any of the orders a server could send; otherwise the first
    // order's result
    if (!na && (ret == 0)) {
        int first = 0;
        for (int p = 0; p < count; p++) {
            uint32_t f;
            int r = verify(leaf, inter, orders[p], n, &trusted, bundle, host, &f);
            if (r == 0) {
                first = 0;
                flags = 0;
                break;
            }
            if (p == 0) {
                first = r;
                flags = f;
            }
        }
        ret = first;
    }
    if (na) {
        printf("na 0\n");
    } else {
        printf("%d %08x\n", ret, (unsigned)flags);
    }
    fflush(stdout);
    free(b);
    free(leaf.p);
    for (int i = 0; i < n; i++) {
        free(inter[i].p);
    }
    mbedtls_x509_crt_free(&trusted);
}

int main(int argc, char **argv)
{
    if ((argc > 1) && !strcmp(argv[1], "bundle")) {
        mbedtls_x509_crt list;
        mbedtls_x509_crt_init(&list);
        for (int i = 2; i < argc; i++) {
            der_t d = unhex(argv[i]);
            if (mbedtls_x509_crt_parse_der(&list, d.p, d.len) != 0) {
                fprintf(stderr, "certificate %d does not parse\n", i - 1);
                return 1;
            }
            free(d.p);
        }
        size_t size;
        unsigned char *b = make_bundle(&list, &size);
        for (size_t i = 0; i < size; i++) {
            printf("%02x", b[i]);
        }
        printf("\n");
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        run_line(line);
    }
    free(line);
    return 0;
}
