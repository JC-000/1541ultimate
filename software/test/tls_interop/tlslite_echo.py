#!/usr/bin/env python3
"""A TLS 1.3 echo server on tlslite-ng (pure Python), for the interop matrix
(interop.py): a third independent implementation, and one that can be made to
break the protocol in exactly one place, which OpenSSL and GnuTLS refuse to do.

    tlslite_echo.py --port N --cert CHAIN --key KEY [--tickets N]
                    [--break finished|cv-context|cv-scheme:NAME]
                    [--empty N] [--empty-where before|after]
    tlslite_echo.py --version

--break finished: the server's Finished carries a wrong verify_data (last
  byte flipped), correctly encrypted.
--break cv-context: the CertificateVerify is signed over the client's context
  string ("TLS 1.3, client CertificateVerify") instead of the server's.
--break cv-scheme:NAME: the CertificateVerify uses signature scheme NAME
  (tlslite's name, e.g. ecdsa_sha1 or rsa_pkcs1_sha256) whatever the client offered.
--empty N: N empty application data records (RFC 8446 section 5.1 allows them)
  before (or after) each chunk of the echo.

Prints SERVER_LISTENING, SERVER_NEGOTIATED ..., SERVER_DONE ... like gnutls_echo:
the version, suite and server_name as the connection has them, the tickets it
actually sent (counted as they are made), and the SHA-256 of what it received.
Gives up after 30 s without a connection.
"""
import argparse
import hashlib
import os
import socket
import sys

if sys.argv[1:] == ["--version"]:
    import tlslite
    import ecdsa
    print("tlslite-ng %s ecdsa %s" % (tlslite.__version__, ecdsa.__version__))
    sys.exit(0)

import tlslite
from tlslite.api import HandshakeSettings, TLSConnection, X509CertChain, parsePEMKey
from tlslite import messages, tlsconnection
from tlslite.keyexchange import KeyExchange


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--tickets", type=int, default=0)
    ap.add_argument("--break", dest="brk", default="")
    ap.add_argument("--empty", type=int, default=0)
    ap.add_argument("--empty-where", default="before", choices=("before", "after"))
    a = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    tickets = [0]
    nst_create = messages.NewSessionTicket.create

    def counted_ticket(self, *args, **kwargs):
        tickets[0] += 1
        return nst_create(self, *args, **kwargs)
    messages.NewSessionTicket.create = counted_ticket

    if a.brk == "finished":
        create = messages.Finished.create

        def bad_finished(self, verify_data):
            verify_data = bytearray(verify_data)
            verify_data[-1] ^= 0x01
            return create(self, verify_data)
        messages.Finished.create = bad_finished
    elif a.brk == "cv-context":
        calc = KeyExchange.calcVerifyBytes

        def bad_context(version, hashes, alg, pms, cr, sr, prf_name=None, peer_tag=b'client', key_type="rsa"):
            if version == (3, 4) and peer_tag == b'server':
                peer_tag = b'client'
            return calc(version, hashes, alg, pms, cr, sr, prf_name, peer_tag, key_type)
        KeyExchange.calcVerifyBytes = staticmethod(bad_context)
    elif a.brk.startswith("cv-scheme:"):
        forced = a.brk.split(":", 1)[1]
        pick = tlsconnection.TLSConnection._pickServerKeyExchangeSig

        def forced_scheme(settings, clientHello, certList=None, private_key=None, version=(3, 3), check_alt=True):
            name, certs, key = pick(settings, clientHello, certList, private_key, version, check_alt)
            return (forced if version > (3, 3) else name), certs, key
        tlsconnection.TLSConnection._pickServerKeyExchangeSig = staticmethod(forced_scheme)
    elif a.brk:
        sys.exit("unknown --break " + a.brk)

    chain = X509CertChain()
    chain.parsePemList(open(a.cert).read())
    key = parsePEMKey(open(a.key).read(), private=True)
    settings = HandshakeSettings()
    settings.minVersion = (3, 4)
    settings.maxVersion = (3, 4)
    settings.ticket_count = a.tickets
    settings.ticketKeys = [os.urandom(32)]

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.port))
    ls.listen(1)
    ls.settimeout(30)
    print("SERVER_LISTENING tlslite-ng %s" % tlslite.__version__)
    s, _ = ls.accept()
    ls.close()
    s.settimeout(20)
    conn = TLSConnection(s)
    received, h, end = 0, hashlib.sha256(), "eof"
    try:
        conn.handshakeServer(certChain=chain, privateKey=key, settings=settings)
    except Exception as e:
        print("SERVER_HANDSHAKE_FAILED %r" % e)
        print("SERVER_DONE received=0 echoed=0 sha256=%s tickets_sent=%d keyupdates_sent=0 end=handshake_failed"
              % (h.hexdigest(), tickets[0]))
        return 0
    version = {(3, 4): "TLS1.3", (3, 3): "TLS1.2"}.get(tuple(conn.version), str(conn.version))
    print("SERVER_NEGOTIATED version=%s suite=%s group=unknown hrr=unknown sni=%s break=%s empty=%d" % (
        version, conn.getCipherName(), getattr(conn.session, "serverName", "") or "-", a.brk or "none", a.empty))
    try:
        while True:
            d = conn.recv(16384)
            if not d:
                end = "peer_close_notify"
                break
            received += len(d)
            h.update(d)
            if a.empty_where == "before":
                for _ in range(a.empty):
                    conn.write(b"")
            conn.sendall(d)
            if a.empty_where == "after":
                for _ in range(a.empty):
                    conn.write(b"")
    except Exception as e:
        end = "%s" % type(e).__name__
    print("SERVER_DONE received=%d echoed=%d sha256=%s tickets_sent=%d keyupdates_sent=0 end=%s" % (
        received, received, h.hexdigest(), tickets[0], end))
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
