/*
 * gnutls_echo.c
 *
 * A TLS 1.3 echo server on GnuTLS, for the interop matrix (interop.py): an
 * implementation independent of mbedTLS and OpenSSL. It serves one connection
 * on 127.0.0.1 and reports what IT negotiated and sent, so no result rests on
 * the engine's own claims.
 *
 *   gnutls_echo --port N --cert CHAIN --key KEY --prio STRING [--tickets N]
 *               [--keyupdate-after BYTES] [--close-after BYTES] [--eof-after BYTES]
 *               [--skip-key-check]
 *
 * --tickets: NewSessionTickets sent right after the handshake (default 0).
 * --keyupdate-after: send a KeyUpdate once this many bytes were echoed.
 * --close-after / --eof-after: once this many bytes were echoed, end with a
 *   close_notify, or with a bare TCP close.
 * --skip-key-check: load a key that does not match the certificate.
 */

#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int hrr_sent, tickets_sent, keyupdates_sent;

static int hook(gnutls_session_t s, unsigned int htype, unsigned when, unsigned int incoming, const gnutls_datum_t *msg)
{
    if (incoming) {
        return 0;
    }
    if (htype == GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST) {
        hrr_sent++;
    } else if (htype == GNUTLS_HANDSHAKE_NEW_SESSION_TICKET) {
        tickets_sent++;
    } else if (htype == GNUTLS_HANDSHAKE_KEY_UPDATE) {
        keyupdates_sent++;
    }
    return 0;
}

static void check(int ret, const char *what)
{
    if (ret < 0) {
        printf("SERVER_SETUP_FAILED %s: %s\n", what, gnutls_strerror(ret));
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int port = 0, tickets = 0, skip_key_check = 0;
    long keyupdate_after = -1, close_after = -1, eof_after = -1;
    const char *cert = NULL, *key = NULL, *prio = NULL;
    for (int i = 1; i < argc; i++) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : "";
        if (!strcmp(k, "--skip-key-check")) { skip_key_check = 1; continue; }
        if (!strcmp(k, "--port")) port = atoi(v);
        else if (!strcmp(k, "--cert")) cert = v;
        else if (!strcmp(k, "--key")) key = v;
        else if (!strcmp(k, "--prio")) prio = v;
        else if (!strcmp(k, "--tickets")) tickets = atoi(v);
        else if (!strcmp(k, "--keyupdate-after")) keyupdate_after = atol(v);
        else if (!strcmp(k, "--close-after")) close_after = atol(v);
        else if (!strcmp(k, "--eof-after")) eof_after = atol(v);
        else { fprintf(stderr, "unknown option %s\n", k); return 2; }
        i++;
    }
    if (!port || !cert || !key || !prio) {
        fprintf(stderr, "usage: see gnutls_echo.c\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    check(gnutls_global_init(), "global_init");
    gnutls_certificate_credentials_t cred;
    check(gnutls_certificate_allocate_credentials(&cred), "credentials");
    if (skip_key_check) {
        gnutls_certificate_set_flags(cred, GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH);
    }
    check(gnutls_certificate_set_x509_key_file(cred, cert, key, GNUTLS_X509_FMT_PEM), "key_file");
    gnutls_datum_t ticket_key;
    check(gnutls_session_ticket_key_generate(&ticket_key), "ticket_key");

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 1)) {
        perror("bind");
        return 1;
    }
    printf("SERVER_LISTENING gnutls %s\n", gnutls_check_version(NULL));
    int fd = accept(ls, NULL, NULL);
    close(ls);

    gnutls_session_t s;
    check(gnutls_init(&s, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET), "init");
    const char *err_pos = NULL;
    int ret = gnutls_priority_set_direct(s, prio, &err_pos);
    if (ret < 0) {
        printf("SERVER_SETUP_FAILED priority at '%s': %s\n", err_pos ? err_pos : "", gnutls_strerror(ret));
        return 1;
    }
    check(gnutls_credentials_set(s, GNUTLS_CRD_CERTIFICATE, cred), "credentials_set");
    check(gnutls_session_ticket_enable_server(s, &ticket_key), "tickets");
    gnutls_handshake_set_hook_function(s, GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_POST, hook);
    gnutls_transport_set_int(s, fd);
    gnutls_handshake_set_timeout(s, 20000);

    do {
        ret = gnutls_handshake(s);
    } while (ret < 0 && !gnutls_error_is_fatal(ret));
    if (ret < 0) {
        gnutls_alert_send_appropriate(s, ret);
        printf("SERVER_HANDSHAKE_FAILED %s hrr=%d\n", gnutls_strerror(ret), hrr_sent);
        printf("SERVER_DONE received=0 echoed=0 tickets_sent=0 keyupdates_sent=0 end=handshake_failed\n");
        close(fd);
        return 0;
    }
    printf("SERVER_NEGOTIATED version=%s suite=%s group=%s hrr=%d\n",
           gnutls_protocol_get_name(gnutls_protocol_get_version(s)), gnutls_ciphersuite_get(s),
           gnutls_group_get_name(gnutls_group_get(s)), hrr_sent);
    if (tickets > 0) {
        check(gnutls_session_ticket_send(s, tickets, 0), "ticket_send");
    }

    char buf[16384];
    long received = 0, echoed = 0;
    const char *end = "eof";
    for (;;) {
        if (close_after >= 0 && echoed >= close_after) {
            gnutls_bye(s, GNUTLS_SHUT_WR);
            end = "sent_close_notify";
            break;
        }
        if (eof_after >= 0 && echoed >= eof_after) {
            end = "sent_bare_tcp_close";
            break;
        }
        ssize_t n = gnutls_record_recv(s, buf, sizeof(buf));
        if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
            continue;
        }
        if (n == 0) {
            end = "peer_close_notify";
            break;
        }
        if (n < 0) {
            end = (n == GNUTLS_E_PREMATURE_TERMINATION) ? "peer_tcp_close" : gnutls_strerror((int)n);
            break;
        }
        received += n;
        for (ssize_t off = 0; off < n; ) {
            ssize_t w = gnutls_record_send(s, buf + off, n - off);
            if (w < 0 && gnutls_error_is_fatal((int)w)) {
                end = gnutls_strerror((int)w);
                goto done;
            }
            if (w > 0) {
                off += w;
            }
        }
        echoed += n;
        if (keyupdate_after >= 0 && echoed >= keyupdate_after && !keyupdates_sent) {
            check(gnutls_session_key_update(s, 0), "key_update");
        }
    }
done:
    printf("SERVER_DONE received=%ld echoed=%ld tickets_sent=%d keyupdates_sent=%d end=%s\n", received, echoed,
           tickets_sent, keyupdates_sent, end);
    close(fd);
    gnutls_deinit(s);
    return 0;
}
