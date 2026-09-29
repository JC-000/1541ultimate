#!/usr/bin/env python3
"""TLS interop matrix for the ESP32's TLS engine (tls_engine.c), run on the host.

nios_pump drives the engine through the CMD_TLS_* handlers the way the Ultimate
does (software/io/wifi/wifi_tls_spike.cc); this script puts an independent TLS 1.3
server at the other end of its socket, one server process per case, and judges
each case from what the SERVER reports it negotiated and sent (OpenSSL's -trace
of its own messages, the GnuTLS server's report), never from the engine's claims.

    interop.py pki --openssl OPENSSL --pki DIR
    interop.py run --pump PUMP --gnutls GNUTLS_ECHO --openssl OPENSSL --pki DIR --out DIR [--only REGEX] [--baud N]

Prints one line per case and, last, "TLS_INTEROP PASS|FAIL n/m".
"""

import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import zlib

# ---------------------------------------------------------------- the PKI

LEAF_EXT = """basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = none
authorityKeyIdentifier = none
"""
CA_EXT = """basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""


def make_pki(openssl, d):
    """A throwaway PKI: an ECDSA P-256 and an RSA-2048 chain (root, intermediate, leaf), and the bad ones."""
    os.makedirs(d, exist_ok=True)

    def run(*a):
        subprocess.run([openssl] + list(a), cwd=d, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def key(name, kind):
        if kind == "ec":
            run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", name + ".key")
        else:
            run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", name + ".key")

    def write(name, text):
        with open(os.path.join(d, name), "w") as f:
            f.write(text)

    write("leaf.ext", LEAF_EXT)
    write("ca.ext", CA_EXT)

    def root(name, kind, cn):
        key(name, kind)
        run("req", "-x509", "-new", "-key", name + ".key", "-subj", "/CN=" + cn, "-days", "3650",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-out", name + ".pem")

    def signed(name, issuer, ext, subj, keyname=None, dates=None, issuer_key=None):
        keyname = keyname or name
        run("req", "-new", "-key", keyname + ".key", "-subj", subj, "-out", name + ".csr")
        a = ["x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem", "-CAkey", (issuer_key or issuer) + ".key",
             "-set_serial", str(int.from_bytes(os.urandom(8), "big")), "-extfile", ext, "-out", name + ".pem"]
        a += ["-not_before", dates[0], "-not_after", dates[1]] if dates else ["-days", "3650"]
        run(*a)

    for kind in ("ec", "rsa"):
        root("root_" + kind, kind, "Interop Test Root " + kind.upper())
        key("int_" + kind, kind)
        signed("int_" + kind, "root_" + kind, "ca.ext", "/CN=Interop Test Intermediate " + kind.upper())
        key("leaf_" + kind, kind)
        signed("leaf_" + kind, "int_" + kind, "leaf.ext", "/CN=localhost")
    # Bad leaves, all under the EC intermediate unless said otherwise
    signed("expired", "int_ec", "leaf.ext", "/CN=localhost", keyname="leaf_ec",
           dates=("20200101000000Z", "20210101000000Z"))
    signed("notyet", "int_ec", "leaf.ext", "/CN=localhost", keyname="leaf_ec",
           dates=("20990101000000Z", "21000101000000Z"))
    root("rogue_root", "ec", "Interop Test Root EC")  # same name as the trusted root, other key
    key("rogue_int", "ec")
    signed("rogue_int", "rogue_root", "ca.ext", "/CN=Interop Test Intermediate EC")
    signed("untrusted", "rogue_int", "leaf.ext", "/CN=localhost", keyname="leaf_ec")
    # Names the real intermediate as its issuer, signed by the rogue one: sent with the REAL intermediate
    signed("forged", "rogue_int", "leaf.ext", "/CN=localhost", keyname="leaf_ec")
    key("other", "ec")  # a key that matches no certificate

    for kind in ("ec", "rsa"):
        write("chain_%s.pem" % kind, open(os.path.join(d, "int_%s.pem" % kind)).read())
    write("chain_rogue.pem", open(os.path.join(d, "rogue_int.pem")).read())
    for leaf, chain in (("leaf_ec", "int_ec"), ("leaf_rsa", "int_rsa"), ("expired", "int_ec"),
                        ("notyet", "int_ec"), ("untrusted", "rogue_int"), ("forged", "int_ec")):
        write("full_%s.pem" % leaf, open(os.path.join(d, leaf + ".pem")).read() +
              open(os.path.join(d, chain + ".pem")).read())
    write("trust.pem", open(os.path.join(d, "root_ec.pem")).read() + open(os.path.join(d, "root_rsa.pem")).read())
    for f in os.listdir(d):
        if f.endswith(".csr") or f.endswith(".srl"):
            os.remove(os.path.join(d, f))
    print("PKI_OK", d)


# ---------------------------------------------------------------- names

# IANA code points (RFC 8446 section B.4, RFC 8446 section 4.2.7)
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
          0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
          0x1305: "TLS_AES_128_CCM_8_SHA256"}
GNUTLS_CIPHER = {0x1301: "AES-128-GCM", 0x1302: "AES-256-GCM", 0x1303: "CHACHA20-POLY1305",
                 0x1304: "AES-128-CCM", 0x1305: "AES-128-CCM-8"}
GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001d: "x25519", 0x001e: "x448"}
HRR_RANDOM_TAIL = "E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"  # s_server -trace prints bytes 4-31
OPENSSL_GROUP = {"x25519": "X25519", "secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
OPENSSL_TRACE_GROUP = {"x25519": "ecdh_x25519", "secp256r1": "secp256r1", "secp384r1": "secp384r1",
                       "secp521r1": "secp521r1"}
GNUTLS_GROUP = {"x25519": "X25519", "secp256r1": "SECP256R1", "secp384r1": "SECP384R1", "secp521r1": "SECP521R1"}


def engine_offer(pump):
    """The cipher suites and groups the engine offers, from the mbedTLS it was built with."""
    out = subprocess.run([pump, "--list"], check=True, capture_output=True, text=True).stdout
    suites, groups = [], []
    for line in out.splitlines():
        if line.startswith("SUITES"):
            suites = [int(x.split(":")[1], 16) for x in line.split()[1:]]
        if line.startswith("GROUPS"):
            groups = [int(x, 16) for x in line.split()[1:]]
    return suites, groups


# ---------------------------------------------------------------- servers

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port, proc, limit=5.0):
    end = time.time() + limit
    while time.time() < end:
        if proc.poll() is not None:
            return False
        out = subprocess.run(["lsof", "-nP", "-iTCP@127.0.0.1:%d" % port, "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True).stdout
        if str(proc.pid) in out.split():
            return True
        time.sleep(0.02)
    return False


class OpenSSLServer:
    """s_server -quiet: what the client sends comes out on stdout, and a relay puts it back on stdin."""

    def __init__(self, openssl, pki, out, name, cert="leaf_ec", suite=None, group=None, tickets=2, tls12=False,
                 end_after=None, end="none"):
        self.port = free_port()
        self.trace = os.path.join(out, name + ".server.trace")
        chain = {"leaf_ec": "int_ec", "leaf_rsa": "int_rsa", "expired": "int_ec", "notyet": "int_ec",
                 "untrusted": "rogue_int", "forged": "int_ec"}[cert]
        key = {"leaf_rsa": "leaf_rsa"}.get(cert, "leaf_ec")
        cmd = [openssl, "s_server", "-accept", "127.0.0.1:%d" % self.port, "-cert", os.path.join(pki, cert + ".pem"),
               "-cert_chain", os.path.join(pki, chain + ".pem"), "-key", os.path.join(pki, key + ".key"),
               "-quiet", "-trace", "-msgfile", self.trace, "-naccept", "1", "-no_ign_eof"]
        if tls12:
            cmd += ["-tls1_2"]
        else:
            cmd += ["-tls1_3", "-num_tickets", str(tickets)]
            if suite:
                cmd += ["-ciphersuites", SUITES[suite]]
            if suite == 0x1305:
                cmd += ["-cipher", "DEFAULT:@SECLEVEL=0"]  # OpenSSL counts CCM_8's 64-bit tag as too weak
            if group:
                cmd += ["-groups", OPENSSL_GROUP[group]]
        self.cmd = cmd
        self.end_after = end_after
        self.end = end
        self.relayed = 0
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ready = wait_listening(self.port, self.proc)
        self.relay = threading.Thread(target=self._relay, daemon=True)
        self.relay.start()

    def _relay(self):
        fin, fout = self.proc.stdout.fileno(), self.proc.stdin.fileno()
        try:
            while True:
                if self.end_after is not None and self.relayed >= self.end_after:
                    if self.end == "close":
                        self.proc.stdin.close()  # -no_ign_eof: s_server ends the connection
                    elif self.end == "eof":
                        time.sleep(0.3)  # s_server sends the last bytes back first
                        self.proc.send_signal(signal.SIGKILL)  # a bare TCP close, no close_notify
                    return
                d = os.read(fin, 65536)
                if not d:
                    return
                self.relayed += len(d)
                os.write(fout, d)
        except OSError:
            return

    def stop(self):
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.relay.join(timeout=2)
        self.stderr = self.proc.stderr.read().decode(errors="replace")
        return self.facts()

    def facts(self):
        """What s_server's trace says it SENT: ServerHello (or HRR) contents, tickets, key updates, alerts."""
        f = {"server": "openssl", "relayed": self.relayed, "tickets": 0, "hrr": 0, "version": None, "suite": None,
             "group": None, "keyupdates": 0, "alerts_sent": [], "handshake_done": False}
        try:
            lines = open(self.trace, errors="replace").read().splitlines()
        except OSError:
            return f
        sent = False
        msg = None
        in_versions = False
        for ln in lines:
            if ln.startswith("Sent TLS Record") or ln.startswith("Sent Record"):
                sent = True
                msg = None
            elif ln.startswith("Received TLS Record") or ln.startswith("Received Record"):
                sent = False
                msg = None
            if not sent:
                continue
            m = re.match(r"\s+(\w+), Length=", ln)
            if m:
                msg = m.group(1)
                if msg == "NewSessionTicket":
                    f["tickets"] += 1
                if msg == "KeyUpdate":
                    f["keyupdates"] += 1
                if msg == "Finished":
                    f["handshake_done"] = True
                continue
            if msg == "ServerHello":
                # A HelloRetryRequest is a ServerHello with this random (RFC 8446 section 4.1.3)
                if "random_bytes" in ln and HRR_RANDOM_TAIL in ln:
                    f["hrr"] += 1
                m = re.search(r"cipher_suite \{0x([0-9A-Fa-f]{2}), 0x([0-9A-Fa-f]{2})\}", ln)
                if m:
                    f["suite"] = int(m.group(1) + m.group(2), 16)
                m = re.search(r"NamedGroup: (\S+)", ln)
                if m:
                    f["group"] = m.group(1)
                if "supported_versions" in ln:
                    in_versions = True
                    continue
                m = re.match(r"\s+TLS 1\.\d \((\d+)\)", ln)
                if m and in_versions:
                    f["version"] = int(m.group(1))
                in_versions = False
            m = re.search(r"Level=\w+\(\d+\), description=([\w ]+)\(\d+\)", ln)
            if m:
                f["alerts_sent"].append(m.group(1).strip())
        f["trace_lines"] = len(lines)
        return f


class GnuTLSServer:
    def __init__(self, gnutls, pki, out, name, cert="leaf_ec", suite=None, group=None, tickets=0, tls12=False,
                 keyupdate_after=None, end_after=None, end="none", key=None):
        self.port = free_port()
        self.log = os.path.join(out, name + ".server.log")
        chain = os.path.join(pki, "full_%s.pem" % cert)
        key = os.path.join(pki, (key or {"leaf_rsa": "leaf_rsa"}.get(cert, "leaf_ec")) + ".key")
        if tls12:
            prio = "NORMAL:-VERS-ALL:+VERS-TLS1.2"
        else:
            prio = "NORMAL:-VERS-ALL:+VERS-TLS1.3"
            if suite:
                prio += ":-CIPHER-ALL:+" + GNUTLS_CIPHER[suite]
            if group:
                prio += ":-GROUP-ALL:+GROUP-" + GNUTLS_GROUP[group]
        cmd = [gnutls, "--port", str(self.port), "--cert", chain, "--key", key, "--prio", prio,
               "--tickets", str(tickets)]
        if keyupdate_after is not None:
            cmd += ["--keyupdate-after", str(keyupdate_after)]
        if end_after is not None and end == "close":
            cmd += ["--close-after", str(end_after)]
        if end_after is not None and end == "eof":
            cmd += ["--eof-after", str(end_after)]
        if key.endswith("other.key"):
            cmd += ["--skip-key-check"]
        self.cmd = cmd
        self.logf = open(self.log, "w")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        first = self.proc.stdout.readline()
        self.logf.write(first)
        self.ready = first.startswith("SERVER_LISTENING")

    def stop(self):
        try:
            out, _ = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
        self.logf.write(out)
        self.logf.close()
        return self.facts()

    def facts(self):
        f = {"server": "gnutls", "tickets": 0, "hrr": 0, "version": None, "suite": None, "group": None,
             "keyupdates": 0, "received": 0, "handshake_done": False}
        for ln in open(self.log).read().splitlines():
            if ln.startswith("SERVER_NEGOTIATED"):
                kv = dict(x.split("=", 1) for x in ln.split()[1:])
                f.update(version=kv["version"], suite=kv["suite"], group=kv["group"], hrr=int(kv["hrr"]))
                f["handshake_done"] = True
            if ln.startswith("SERVER_DONE"):
                head, _, end = ln.partition(" end=")  # the end may be an error message with spaces
                kv = dict(x.split("=", 1) for x in head.split()[1:])
                kv["end"] = end
                f.update(tickets=int(kv["tickets_sent"]), keyupdates=int(kv["keyupdates_sent"]),
                         received=int(kv["received"]), end=kv["end"])
            if ln.startswith("SERVER_HANDSHAKE_FAILED"):
                f["handshake_error"] = ln.split(" ", 1)[1]
        return f


class TamperProxy:
    """Between the pump and a server: changes the server's bytes, one record chosen by its position."""

    def __init__(self, target_port, mode, record_index):
        self.mode, self.index = mode, record_index
        self.target = target_port
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.done = ""
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        c, _ = self.ls.accept()
        s = socket.create_connection(("127.0.0.1", self.target))
        up = threading.Thread(target=self._pipe, args=(c, s), daemon=True)
        up.start()
        buf, n = b"", 0
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
                out = b""
                while len(buf) >= 5:
                    ln = int.from_bytes(buf[3:5], "big")
                    if len(buf) < 5 + ln:
                        break
                    rec, buf = bytearray(buf[:5 + ln]), buf[5 + ln:]
                    if n == self.index:
                        if self.mode == "flip":
                            rec[5 + ln // 2] ^= 0x01
                            self.done = "flipped byte %d of record %d (type %d, length %d)" % (ln // 2, n, rec[0], ln)
                        elif self.mode == "shorten":
                            rec[3:5] = (ln - 16).to_bytes(2, "big")
                            self.done = "record %d length %d -> %d" % (n, ln, ln - 16)
                        elif self.mode == "truncate":
                            c.sendall(out + bytes(rec[:5 + ln // 2]))
                            self.done = "sent %d of record %d's %d bytes, then closed" % (ln // 2, n, ln)
                            c.close()
                            s.close()
                            return
                    out += bytes(rec)
                    n += 1
                if out:
                    c.sendall(out)
        except OSError:
            pass
        for x in (c, s):
            try:
                x.close()
            except OSError:
                pass

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


# ---------------------------------------------------------------- cases

class Case:
    def __init__(self, name, server, sargs, pump, expect, proxy=None, note=""):
        self.name, self.server, self.sargs, self.pump, self.expect, self.proxy, self.note = \
            name, server, sargs, pump, expect, proxy, note


PAYLOADS = [1, 511, 512, 1024, 3000, 16500]
# (label, pt per step, ct per step: 0 is what the step has room for, as the Nios reads)
CHUNKINGS = [("pt512", 512, 0), ("pt1024", 1024, 0), ("pt512-ct1", 512, 1), ("pt512-ct1500", 512, 1500)]
TICKETS = [0, 1, 2, 8]


def matrix(suites, groups):
    cases = []
    first, second = GROUPS[groups[0]], "secp256r1"
    grouplist = [(first, 0), (second, 0 if first == second else 1)]
    for srv in ("openssl", "gnutls"):
        default_tickets = 2
        # Handshake parameters: every suite the engine offers x groups (and an HRR) x both chains
        for suite in suites:
            for g, hrr in grouplist:
                for cert in ("leaf_ec", "leaf_rsa"):
                    name = "%s/params/%s/%s%s/%s" % (srv, SUITES[suite], g, "-hrr" if hrr else "",
                                                     cert.replace("leaf_", ""))
                    cases.append(Case(name, srv, dict(cert=cert, suite=suite, group=g, tickets=default_tickets),
                                      dict(echo=3000, pt=512, ct=0),
                                      dict(ok=True, suite=suite, group=g, hrr=hrr, tickets=default_tickets)))
        # Traffic shapes: tickets x payload x chunking
        for t in TICKETS:
            for n in PAYLOADS:
                for label, pt, ct in CHUNKINGS:
                    name = "%s/shape/tickets%d/%dB/%s" % (srv, t, n, label)
                    cases.append(Case(name, srv, dict(tickets=t), dict(echo=n, pt=pt, ct=ct),
                                      dict(ok=True, tickets=t)))
        # A burst: every ticket (and the echo behind them) already in the socket at the first echo step
        for t in (2, 4, 5, 8):
            for n in (1, 3000):
                cases.append(Case("%s/burst/tickets%d/%dB" % (srv, t, n), srv, dict(tickets=t),
                                  dict(echo=n, pt=512, ct=0, settle=100), dict(ok=True, tickets=t)))
        # Scripted: the echo's one write goes out with no ciphertext; 150 ms later the next step takes
        # the start of the server's flight (one byte, or with 8 tickets about the first three, each
        # ticket record being about 250 bytes from both servers), and the step after it all the rest:
        # up to five tickets and the echo in one step, nothing more to come
        for t in (1, 2, 4, 5, 8):
            first = 1 if t <= 5 else (t - 5) * 250 - 50
            cases.append(Case("%s/burst-after-write/tickets%d/1B" % (srv, t), srv, dict(tickets=t),
                              dict(echo=1, pt=512, ct=0, settle=150, settle_at=1, caps="0,%d" % first),
                              dict(ok=True, tickets=t)))
        # Endings
        cases.append(Case("%s/end/close_notify" % srv, srv, dict(tickets=2, end_after=3000, end="close"),
                          dict(echo=3000, pt=512, ct=0, after="close"), dict(ok=True, outcome="CLOSED", tickets=2)))
        cases.append(Case("%s/end/bare_tcp_close" % srv, srv, dict(tickets=2, end_after=3000, end="eof"),
                          dict(echo=3000, pt=512, ct=0, after="eof"), dict(ok=True, outcome="PEER_CLOSED", tickets=2)))
        # Must fail: nothing may come through
        bad = [("hostname_mismatch", dict(), dict(sni="wrong.example.net")),
               ("untrusted_root", dict(cert="untrusted"), {}),
               ("expired", dict(cert="expired"), {}),
               ("not_yet_valid", dict(cert="notyet"), {}),
               ("tls12_only", dict(tls12=True), {}),
               ("forged_signature", dict(cert="forged"), {})]
        if srv == "gnutls":
            bad.append(("key_mismatch", dict(key="other"), {}))
        for label, s, p in bad:
            cases.append(Case("%s/mustfail/%s" % (srv, label), srv, dict(tickets=2, **s), dict(echo=3000, **p),
                              dict(ok=False)))
    # KeyUpdate from the server, mid-stream (GnuTLS; s_server -quiet cannot be told to)
    cases.append(Case("gnutls/keyupdate/after1024", "gnutls", dict(tickets=2, keyupdate_after=1024),
                      dict(echo=3000, pt=512, ct=0), dict(ok=True, keyupdate=True, tickets=2)))
    # Tampering on the wire, by the server's record number: 0 ServerHello, 1 ChangeCipherSpec, then the
    # encrypted EncryptedExtensions 2, Certificate 3, CertificateVerify 4, Finished 5 (s_server sends
    # one record per message; interop.py checks it in the trace)
    for label, mode, idx in (("serverhello_flip", "flip", 0), ("serverhello_shortened", "shorten", 0),
                             ("serverhello_truncated", "truncate", 0), ("certificate_flip", "flip", 3),
                             ("certverify_flip", "flip", 4), ("finished_flip", "flip", 5)):
        cases.append(Case("openssl/tamper/%s" % label, "openssl", dict(tickets=2), dict(echo=3000),
                          dict(ok=False), proxy=(mode, idx)))
    return cases


def run_case(c, a, out):
    base = re.sub(r"[^\w.-]", "_", c.name)
    if c.server == "openssl":
        srv = OpenSSLServer(a.openssl, a.pki, out, base, **c.sargs)
    else:
        srv = GnuTLSServer(a.gnutls, a.pki, out, base, **c.sargs)
    if not srv.ready:
        srv.stop()
        return False, "server did not start: %s" % " ".join(srv.cmd), {}
    port = srv.port
    proxy = None
    if c.proxy:
        proxy = TamperProxy(port, *c.proxy)
        port = proxy.port
    p = c.pump
    cmd = [a.pump, "--port", str(port), "--sni", p.get("sni", "localhost"), "--echo", str(p.get("echo", 0)),
           "--pt-chunk", str(p.get("pt", 512)), "--ct-chunk", str(p.get("ct", 0)), "--after", p.get("after", "none"),
           "--seed", str(zlib.crc32(c.name.encode())), "--settle-ms", str(p.get("settle", 0)),
           "--settle-at", str(p.get("settle_at", 0))] + (["--ct-caps", p["caps"]] if "caps" in p else [])
    if a.baud is not None:
        cmd += ["--baud", a.baud]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        pump_out, pump_err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        pump_out, pump_err, rc = (e.stdout or b"").decode(), (e.stderr or b"").decode(), -1
    dt = time.time() - t0
    facts = srv.stop()
    with open(os.path.join(out, base + ".pump.log"), "w") as f:
        f.write(" ".join(cmd) + "\n" + pump_out + pump_err)
    res = {}
    for ln in pump_out.splitlines():
        if ln.startswith("RESULT "):
            res = dict(re.findall(r"(\w+)=(\S*)", ln))
    return judge(c, res, facts, pump_err, rc, proxy, dt)


def judge(c, res, facts, pump_err, rc, proxy, dt):
    why = []
    e = c.expect
    if rc != 0 or "Sanitizer" in pump_err or "runtime error" in pump_err:
        why.append("pump exit %d / sanitizer: %s" % (rc, pump_err.strip().splitlines()[-1:] or ""))
    if not res:
        why.append("no RESULT line")
        return False, "; ".join(why), facts
    outcome = res.get("outcome")
    detail = "outcome=%s esp_err=%s state=%s pt_delivered=%s echo_received=%s steps=%s" % (
        outcome, res.get("esp_err"), res.get("state"), res.get("pt_delivered"), res.get("echo_received"),
        res.get("steps"))
    if e["ok"]:
        want = e.get("outcome", "ECHO_OK")
        if e.get("keyupdate"):
            # mbedTLS 3.6.0 has no KeyUpdate: the engine must fail cleanly, with every byte before it intact
            if outcome != "FAILED" or res.get("esp_err") != "-0x7700":
                why.append("KeyUpdate: expected FAILED -0x7700 (UNEXPECTED_MESSAGE), got %s" % outcome)
            if int(res.get("echo_received", -1)) < 1024:
                why.append("bytes before the KeyUpdate lost")
            if facts.get("keyupdates") != 1:
                why.append("server sent %s KeyUpdates" % facts.get("keyupdates"))
        else:
            if outcome != want:
                why.append("outcome %s, want %s" % (outcome, want))
            if res.get("echo_ok") != "1" or res.get("echo_received") != str(c.pump["echo"]):
                why.append("echo not intact")
        # A killed s_server loses the end of its trace: then the echo it relayed is the witness
        killed = c.server == "openssl" and c.sargs.get("end") == "eof"
        if not facts.get("handshake_done") and not killed:
            why.append("server saw no completed handshake")
        if c.server == "openssl" and killed:
            if facts.get("relayed") != c.pump["echo"]:
                why.append("server relayed %s of %d" % (facts.get("relayed"), c.pump["echo"]))
        elif c.server == "openssl":
            if facts.get("version") != 0x0304:
                why.append("server version %s" % facts.get("version"))
            if not e.get("keyupdate") and facts.get("relayed", 0) < c.pump["echo"] and outcome == "ECHO_OK":
                why.append("server relayed %s of %d" % (facts.get("relayed"), c.pump["echo"]))
            if "suite" in e and facts.get("suite") != e["suite"]:
                why.append("server chose suite %s" % facts.get("suite"))
            if "group" in e and facts.get("group") != OPENSSL_TRACE_GROUP[e["group"]]:
                why.append("server chose group %s" % facts.get("group"))
        else:
            if facts.get("version") != "TLS1.3":
                why.append("server version %s" % facts.get("version"))
            if "suite" in e and not (facts.get("suite") or "").endswith(SUITES[e["suite"]][4:]):
                why.append("server chose suite %s" % facts.get("suite"))
            if "group" in e and facts.get("group") != GNUTLS_GROUP[e["group"]]:
                why.append("server chose group %s" % facts.get("group"))
        if "hrr" in e and facts.get("hrr") != e["hrr"]:
            why.append("server HRR %s, want %s" % (facts.get("hrr"), e["hrr"]))
        if "tickets" in e and not killed and facts.get("tickets") != e["tickets"]:
            why.append("server sent %s tickets, want %s" % (facts.get("tickets"), e["tickets"]))
    else:
        if outcome not in ("FAILED", "PEER_CLOSED"):
            why.append("outcome %s, want FAILED" % outcome)
        if outcome == "PEER_CLOSED" and not (proxy and proxy.mode == "truncate"):
            why.append("ended by the server, not by the engine")
        if res.get("pt_delivered") != "0" or res.get("echo_sent") != "0":
            why.append("plaintext moved: delivered %s, sent %s" % (res.get("pt_delivered"), res.get("echo_sent")))
        if facts.get("relayed", 0) or facts.get("received", 0):
            why.append("server received application data")
        if proxy and not proxy.done:
            why.append("proxy never tampered")
    if proxy:
        detail += " proxy: " + proxy.done
    return not why, detail + ("" if not why else " || " + "; ".join(why)), facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("pki", "run"))
    ap.add_argument("--openssl", required=True)
    ap.add_argument("--pki", required=True)
    ap.add_argument("--pump")
    ap.add_argument("--gnutls")
    ap.add_argument("--out")
    ap.add_argument("--only")
    ap.add_argument("--baud", help="the pump's serial-link model (0: none; default: the pump's)")
    a = ap.parse_args()
    if a.what == "pki":
        make_pki(a.openssl, a.pki)
        return 0
    os.makedirs(a.out, exist_ok=True)
    suites, groups = engine_offer(a.pump)
    ver_o = subprocess.run([a.openssl, "version"], capture_output=True, text=True).stdout.strip()
    ver_g = subprocess.run(["pkg-config", "--modversion", "gnutls"], capture_output=True, text=True).stdout.strip()
    print("PEERS openssl: %s | gnutls: %s" % (ver_o, ver_g))
    print("ENGINE offers suites %s, groups %s" % (
        ", ".join(SUITES.get(s, hex(s)) for s in suites), ", ".join(GROUPS.get(g, hex(g)) for g in groups)))
    cases = matrix(suites, groups)
    if a.only:
        cases = [c for c in cases if re.search(a.only, c.name)]
    passed = 0
    t0 = time.time()
    for c in cases:
        ok, detail, _ = run_case(c, a, a.out)
        passed += ok
        print("%s %s %s" % ("PASS" if ok else "FAIL", c.name, detail), flush=True)
    print("elapsed %.1f s" % (time.time() - t0))
    print("TLS_INTEROP %s %d/%d" % ("PASS" if passed == len(cases) and cases else "FAIL", passed, len(cases)))
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
