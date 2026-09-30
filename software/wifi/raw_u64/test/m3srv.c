/*
 * m3srv.c
 *
 * The server side of the engine host test (engine_test.c). One connection per run.
 *   m3srv PORT tls OPTIONS...   a TLS server (mbedTLS 3.6.0, default configuration)
 *   m3srv PORT raw:WHAT         no TLS library: reads the ClientHello, logs it, answers WHAT by hand
 * Everything it sees goes to stdout, one "KEY value" line each, for the test to check.
 *
 * tls OPTIONS (key=value):
 *   ver=13|12|1213     versions offered (min and max)
 *   groups=a:b         key-exchange groups, IANA hex (e.g. 0017 or 001d:0017)
 *   crt=FILE key=FILE  server certificate chain and key (PEM)
 *   ems=0              TLS 1.2 without the extended master secret extension
 *   ownusage=0         skip the server's check of its own certificate's (extended) key usage, to serve one that
 *                      the client must refuse (the DER sent is unchanged)
 *   run=TOKENS         what to do after the handshake, comma separated, in order:
 *     app:N        one application data record of N bytes of the test pattern
 *     wa:D / fa:D  a warning / fatal alert with description D (encrypted as the session is)
 *     cn           close_notify
 *     rd:N         read N bytes of plaintext and check them against the client pattern
 *     echo         echo plaintext until close_notify or EOF, then log which one it was
 *     drain        read until close_notify or EOF, log which one it was
 *     sleep:MS     sleep
 *     rst          close with SO_LINGER 0
 * raw WHAT:
 *   ch         nothing (the ClientHello audit only)
 *   sh12       a TLS 1.2 ServerHello (legacy_version 0x0303, no supported_versions)
 *   sh12s      the same with the RFC 8446 4.1.3 downgrade sentinel in its random
 *   sh11       a ServerHello for TLS 1.1 (0x0302)
 *   sh12suite  a TLS 1.2 ServerHello choosing a suite the client never offered (a CBC one mbedTLS still has)
 *   alert70    a plaintext fatal protocol_version alert
 *   cn         a plaintext close_notify warning alert
 *
 * The test pattern: byte i of a direction's plaintext stream is (i * 31 + seed) & 0xFF, seed 7 from the
 * server and 11 from the client.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"
#include "ssl_misc.h"

#define SEED_SERVER 7
#define SEED_CLIENT 11

static uint8_t pattern(long i, int seed) { return (uint8_t)(i * 31 + seed); }

static int listen_on(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 1)) {
        perror("bind/listen");
        exit(2);
    }
    printf("LISTEN %d\n", port);
    fflush(stdout);
    int c = accept(fd, NULL, NULL);
    close(fd);
    return c;
}

static int read_all(int fd, uint8_t *p, int n)
{
    for (int got = 0; got < n; ) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r <= 0) {
            return -1;
        }
        got += (int)r;
    }
    return n;
}

/* ---- raw mode: the ClientHello audit and hand-made answers ---- */

static void hexlist(const char *key, const uint8_t *p, int n, int width)
{
    printf("%s", key);
    for (int i = 0; i + width <= n; i += width) {
        printf("%s", i ? "," : " ");
        for (int j = 0; j < width; j++) {
            printf("%02x", p[i + j]);
        }
    }
    printf("\n");
}

static int audit_client_hello(int fd)
{
    static uint8_t rec[1 << 14];
    uint8_t h[5];
    if (read_all(fd, h, 5) < 0) {
        return -1;
    }
    int len = (h[3] << 8) | h[4];
    if (h[0] != 22 || read_all(fd, rec, len) < 0) {
        return -1;
    }
    const uint8_t *p = rec + 4, *end = rec + 4 + ((rec[1] << 16) | (rec[2] << 8) | rec[3]);
    printf("CH legacy_version %02x%02x\n", p[0], p[1]);
    p += 2 + 32;
    p += 1 + p[0];                                   // session id
    int sl = (p[0] << 8) | p[1];
    hexlist("CH suites", p + 2, sl, 2);
    p += 2 + sl;
    p += 1 + p[0];                                   // compression methods
    const uint8_t *ext = p + 2, *eend = p + 2 + ((p[0] << 8) | p[1]);
    if (eend > end) {
        return -1;
    }
    printf("CH ext");
    for (const uint8_t *e = ext; e + 4 <= eend; e += 4 + ((e[2] << 8) | e[3])) {
        printf("%s%02x%02x", (e == ext) ? " " : ",", e[0], e[1]);
    }
    printf("\n");
    for (const uint8_t *e = ext; e + 4 <= eend; e += 4 + ((e[2] << 8) | e[3])) {
        int type = (e[0] << 8) | e[1], elen = (e[2] << 8) | e[3];
        const uint8_t *d = e + 4;
        if (type == 43) {
            hexlist("CH versions", d + 1, d[0], 2);
        } else if (type == 10) {
            hexlist("CH groups", d + 2, (d[0] << 8) | d[1], 2);
        } else if (type == 13) {
            hexlist("CH sigalgs", d + 2, (d[0] << 8) | d[1], 2);
        } else if (type == 23) {
            printf("CH ems len %d\n", elen);
        } else if (type == 35) {
            printf("CH session_ticket len %d\n", elen);
        } else if (type == 0xff01) {
            printf("CH renegotiation_info len %d\n", elen);
        } else if (type == 0) {
            printf("CH sni %.*s\n", elen - 5, (const char *)d + 5);
        }
    }
    fflush(stdout);
    return 0;
}

static void send_server_hello(int fd, uint16_t version, int sentinel, uint16_t suite)
{
    uint8_t m[128], *p = m + 9; // record header 5 + handshake header 4
    *p++ = version >> 8;
    *p++ = version & 0xFF;
    for (int i = 0; i < 32; i++) {
        *p++ = (uint8_t)(0xA0 + i);
    }
    if (sentinel) {
        memcpy(p - 8, "\x44\x4F\x57\x4E\x47\x52\x44\x01", 8);
    }
    *p++ = 0;                                        // session id
    *p++ = suite >> 8;
    *p++ = suite & 0xFF;
    *p++ = 0;                                        // compression
    static const uint8_t ext[] = { 0x00, 0x04, 0x00, 0x17, 0x00, 0x00 }; // extended_master_secret
    memcpy(p, ext, sizeof(ext));
    p += sizeof(ext);
    int body = (int)(p - m) - 9;
    m[0] = 22; m[1] = 3; m[2] = 3; m[3] = (body + 4) >> 8; m[4] = (body + 4) & 0xFF;
    m[5] = 2; m[6] = 0; m[7] = body >> 8; m[8] = body & 0xFF;
    send(fd, m, p - m, 0);
}

static int raw_mode(int fd, const char *what)
{
    if (audit_client_hello(fd) < 0) {
        printf("CH unreadable\n");
        return 1;
    }
    if (!strcmp(what, "sh12")) {
        send_server_hello(fd, 0x0303, 0, 0xC02B);
    } else if (!strcmp(what, "sh12s")) {
        send_server_hello(fd, 0x0303, 1, 0xC02B);
    } else if (!strcmp(what, "sh11")) {
        send_server_hello(fd, 0x0302, 0, 0xC02B);
    } else if (!strcmp(what, "sh12suite")) {
        send_server_hello(fd, 0x0303, 0, 0xC023);
    } else if (!strcmp(what, "alert70")) {
        send(fd, "\x15\x03\x03\x00\x02\x02\x46", 7, 0);
    } else if (!strcmp(what, "cn")) {
        send(fd, "\x15\x03\x03\x00\x02\x01\x00", 7, 0);
    }
    // Log what the client answers, until it closes
    uint8_t h[5], body[1 << 14];
    while (read_all(fd, h, 5) == 5) {
        int len = (h[3] << 8) | h[4];
        if (read_all(fd, body, len) < 0) {
            break;
        }
        if (h[0] == 21 && len == 2) {
            printf("RX alert %d %d\n", body[0], body[1]);
        } else {
            printf("RX record type %d len %d\n", h[0], len);
        }
    }
    printf("RAW done\n");
    return 0;
}

/* ---- TLS mode ---- */

static mbedtls_ssl_context ssl;
static long tx_total, rx_total;

static int raw_record(int type, const uint8_t *d, size_t n)
{
    ssl.out_msgtype = type;
    ssl.out_msglen = n;
    memcpy(ssl.out_msg, d, n);
    int ret = mbedtls_ssl_write_record(&ssl, 1);
    if (ret) {
        printf("ERR write_record -0x%04x\n", -ret);
    }
    return ret;
}

static void app_record(int n)
{
    static uint8_t b[16384];
    for (int i = 0; i < n; i++) {
        b[i] = pattern(tx_total + i, SEED_SERVER);
    }
    tx_total += n;
    raw_record(MBEDTLS_SSL_MSG_APPLICATION_DATA, b, n);
}

// Reads plaintext until close_notify or EOF; echo sends it back. Checks it against the client pattern.
static void read_to_end(int echo)
{
    uint8_t b[4096];
    int bad = 0;
    for (;;) {
        int n = mbedtls_ssl_read(&ssl, b, sizeof(b));
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                bad += b[i] != pattern(rx_total + i, SEED_CLIENT);
            }
            rx_total += n;
            if (echo) {
                mbedtls_ssl_write(&ssl, b, n);
            }
            continue;
        }
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue;
        }
        printf("RX total %ld bad %d\n", rx_total, bad);
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("RX close_notify\n");
        } else if (n == 0 || n == MBEDTLS_ERR_NET_CONN_RESET) {
            printf("RX eof\n");
        } else {
            printf("RX error -0x%04x\n", -n);
        }
        return;
    }
}

static void run_script(mbedtls_net_context *net, char *script)
{
    for (char *tok = strtok(script, ","); tok; tok = strtok(NULL, ",")) {
        if (!strncmp(tok, "app:", 4)) {
            app_record(atoi(tok + 4));
        } else if (!strncmp(tok, "wa:", 3) || !strncmp(tok, "fa:", 3)) {
            uint8_t a[2] = { (uint8_t)((tok[0] == 'w') ? 1 : 2), (uint8_t)atoi(tok + 3) };
            raw_record(MBEDTLS_SSL_MSG_ALERT, a, 2);
        } else if (!strcmp(tok, "cn")) {
            mbedtls_ssl_close_notify(&ssl);
        } else if (!strncmp(tok, "rd:", 3)) {
            int want = atoi(tok + 3), bad = 0;
            uint8_t b[4096];
            while (want > 0) {
                int n = mbedtls_ssl_read(&ssl, b, want < (int)sizeof(b) ? want : (int)sizeof(b));
                if (n == MBEDTLS_ERR_SSL_WANT_READ) {
                    continue;
                }
                if (n <= 0) {
                    printf("RX error -0x%04x\n", -n);
                    break;
                }
                for (int i = 0; i < n; i++) {
                    bad += b[i] != pattern(rx_total + i, SEED_CLIENT);
                }
                rx_total += n;
                want -= n;
            }
            printf("RX total %ld bad %d\n", rx_total, bad);
        } else if (!strcmp(tok, "echo")) {
            read_to_end(1);
        } else if (!strcmp(tok, "drain")) {
            read_to_end(0);
        } else if (!strncmp(tok, "sleep:", 6)) {
            usleep(atoi(tok + 6) * 1000);
        } else if (!strcmp(tok, "rst")) {
            struct linger l = { 1, 0 };
            setsockopt(net->fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }
        fflush(stdout);
    }
}

static int parse_groups(const char *s, uint16_t *g, int max)
{
    int n = 0;
    while (*s && n < max - 1) {
        g[n++] = (uint16_t)strtoul(s, (char **)&s, 16);
        if (*s == ':') {
            s++;
        }
    }
    g[n] = 0;
    return n;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: m3srv PORT tls|raw:WHAT [options]\n");
        return 2;
    }
    int port = atoi(argv[1]);
    if (!strncmp(argv[2], "raw:", 4)) {
        int fd = listen_on(port);
        int r = raw_mode(fd, argv[2] + 4);
        close(fd);
        return r;
    }

    const char *ver = "1213", *crt = NULL, *key = NULL, *groups = NULL;
    char *script = NULL;
    int ems = 1, ownusage = 1;
    for (int i = 3; i < argc; i++) {
        if (!strncmp(argv[i], "ver=", 4)) ver = argv[i] + 4;
        else if (!strncmp(argv[i], "crt=", 4)) crt = argv[i] + 4;
        else if (!strncmp(argv[i], "key=", 4)) key = argv[i] + 4;
        else if (!strncmp(argv[i], "groups=", 7)) groups = argv[i] + 7;
        else if (!strncmp(argv[i], "ems=", 4)) ems = atoi(argv[i] + 4);
        else if (!strncmp(argv[i], "ownusage=", 9)) ownusage = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "run=", 4)) script = argv[i] + 4;
    }

    psa_crypto_init();
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt chain;
    mbedtls_pk_context pk;
    mbedtls_net_context net;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&chain);
    mbedtls_pk_init(&pk);
    mbedtls_ssl_init(&ssl);
    mbedtls_net_init(&net);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) ||
        mbedtls_x509_crt_parse_file(&chain, crt) ||
        mbedtls_pk_parse_keyfile(&pk, key, NULL, mbedtls_ctr_drbg_random, &drbg) ||
        mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT)) {
        printf("ERR setup\n");
        return 2;
    }
    if (!ownusage) {
        chain.ext_types &= ~(MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE | MBEDTLS_X509_EXT_KEY_USAGE);
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_own_cert(&conf, &chain, &pk);
    mbedtls_ssl_conf_min_tls_version(&conf, strcmp(ver, "13") ? MBEDTLS_SSL_VERSION_TLS1_2 : MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&conf, strcmp(ver, "12") ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_extended_master_secret(&conf, ems ? MBEDTLS_SSL_EXTENDED_MS_ENABLED : MBEDTLS_SSL_EXTENDED_MS_DISABLED);
    static uint16_t g[8];
    if (groups) {
        parse_groups(groups, g, 8);
        mbedtls_ssl_conf_groups(&conf, g);
    }
    if (mbedtls_ssl_setup(&ssl, &conf)) {
        printf("ERR ssl_setup\n");
        return 2;
    }
    net.fd = listen_on(port);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        }
    }
    if (ret != 0) {
        printf("HS fail -0x%04x state %d\n", -ret, ssl.state);
        if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
            printf("HS alert %d\n", ssl.in_msg[1]);
        }
        return 0;
    }
    printf("HS ok version %04x suite %04x ems_conf %d\n", (unsigned)ssl.tls_version,
           (unsigned)mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl), ems);
    if (script) {
        run_script(&net, script);
    }
    printf("END\n");
    mbedtls_net_free(&net);
    return 0;
}
