#!/usr/bin/env python3
"""TLS 1.3 interop matrix: independent servers against a TLS client under test.

The peer side lives here and knows nothing about the client: a throwaway PKI,
one server process per case on 127.0.0.1 (OpenSSL s_server with -trace, the
GnuTLS echo server gnutls_echo.c, and a raw-record peer for HelloRetryRequest
cases), a tampering proxy, the cases, and the verdicts. Every verdict rests on
what the SERVER reports it negotiated, sent and received, never on the client's
claims; the bytes a server echoed are checked against a hash of the payload.

    interop.py pki --openssl OPENSSL --pki DIR
    interop.py run --client CLIENT --gnutls GNUTLS_ECHO --openssl OPENSSL --pki DIR --out DIR
                   [--only REGEX] [--client-arg ARG ...]

Prints one line per case (PASS, XFAIL: a documented limitation of the client's
TLS library, or FAIL) and, last, "TLS_INTEROP PASS|FAIL n/m".

The client contract. CLIENT is an executable; the ESP32's TLS engine is driven
by software/test/wifi_tls_interop/nios_pump.c, and any other client (mbedTLS on
the main CPU over sockets, say) plugs in the same way:

  CLIENT --list
      prints "SUITES name:0xID ..." (the TLS 1.3 suites it offers, in order),
      "GROUPS 0xID ..." (the groups, first = its key share) and optionally
      "INFO <text>" (library, version, configuration), one line each.
  CLIENT --port N --sni NAME --echo BYTES --seed S --after none|close|eof
         --pt-chunk B --ct-chunk B --settle-ms MS --settle-at K [--ct-caps LIST] [ARG ...]
      connects to 127.0.0.1:N, runs a TLS 1.3 handshake with verification on,
      trusting exactly <pki>/trust.pem and checking NAME; sends BYTES bytes, byte
      i being payload(S, i) below; reads the same number back, comparing as they
      come; then with --after close waits for the server's close_notify, with
      --after eof for a TCP close without one. The last stdout line is
      "RESULT outcome=O pt_delivered=N echo_sent=N echo_received=N echo_ok=0|1
      [esp_err=E] [tickets_taken=T] ...", O one of ECHO_OK, CLOSED (close_notify), PEER_CLOSED
      (TCP closed first), FAILED (the TLS layer failed), TIMEOUT, ECHO_MISMATCH,
      CONNECT_FAILED, OPEN_FAILED. pt_delivered counts every plaintext byte the
      TLS layer handed out, in any stage; E is the TLS library's error code; T,
      if given, counts the NewSessionTickets the TLS layer parsed and kept, and
      must equal what the server sent.
      Exit status 0; anything on stderr containing "Sanitizer" or "runtime
      error" fails the case.
  The chunking options describe the traffic shape (plaintext per write,
  ciphertext per read, when reads happen); a client should honour what it can.
"""

import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import hashlib
import struct
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
    """A throwaway PKI: an ECDSA P-256 and an RSA-2048 chain (root, intermediate, leaf), and the bad ones.
    What exists is kept, so a PKI made by an older interop.py only gains the certificates it lacks."""
    os.makedirs(d, exist_ok=True)

    def have(name):
        return os.path.exists(os.path.join(d, name))

    def run(*a):
        subprocess.run([openssl] + list(a), cwd=d, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def key(name, kind):
        if have(name + ".key"):
            return
        if kind == "ec":
            run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", name + ".key")
        else:
            run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", name + ".key")

    def write(name, text):
        p = os.path.join(d, name)
        if not (os.path.exists(p) and open(p).read() == text):  # trust.pem is linked into the client
            with open(p, "w") as f:
                f.write(text)

    write("leaf.ext", LEAF_EXT)
    write("ca.ext", CA_EXT)
    write("eku_client.ext", LEAF_EXT.replace("extendedKeyUsage = serverAuth", "extendedKeyUsage = clientAuth"))
    write("ku_no_ds.ext", LEAF_EXT.replace("keyUsage = critical, digitalSignature", "keyUsage = critical, keyAgreement"))

    def root(name, kind, cn):
        if have(name + ".pem"):
            return
        key(name, kind)
        run("req", "-x509", "-new", "-key", name + ".key", "-subj", "/CN=" + cn, "-days", "3650",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-out", name + ".pem")

    def signed(name, issuer, ext, subj, keyname=None, dates=None, issuer_key=None):
        keyname = keyname or name
        if have(name + ".pem"):
            return
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
    # A server certificate that is not one: for client authentication only, or not for signatures
    signed("eku_client", "int_ec", "eku_client.ext", "/CN=localhost", keyname="leaf_ec")
    signed("ku_no_ds", "int_ec", "ku_no_ds.ext", "/CN=localhost", keyname="leaf_ec")

    # Leaves valid only near the time the PKI step runs: +-2 days, from 20 days on, until 20 days ago.
    # Remade on a new day, so they judge the device clock, whatever the age of the rest of the PKI.
    today = time.strftime("%Y%m%d", time.gmtime())
    stamp = os.path.join(d, "window.day")
    if not (os.path.exists(stamp) and open(stamp).read() == today):
        def at(days):
            return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + days * 86400))
        for name, nb, na in (("win_pm2", -2, 2), ("win_notyet20", 20, 400), ("win_expired20", -400, -20)):
            for ext in (".pem",):
                if os.path.exists(os.path.join(d, name + ext)):
                    os.remove(os.path.join(d, name + ext))
            signed(name, "int_ec", "leaf.ext", "/CN=localhost", keyname="leaf_ec", dates=(at(nb), at(na)))
        with open(stamp, "w") as f:
            f.write(today)

    for kind in ("ec", "rsa"):
        write("chain_%s.pem" % kind, open(os.path.join(d, "int_%s.pem" % kind)).read())
    write("chain_rogue.pem", open(os.path.join(d, "rogue_int.pem")).read())
    for leaf, chain in (("leaf_ec", "int_ec"), ("leaf_rsa", "int_rsa"), ("expired", "int_ec"),
                        ("notyet", "int_ec"), ("untrusted", "rogue_int"), ("forged", "int_ec"),
                        ("eku_client", "int_ec"), ("ku_no_ds", "int_ec"), ("win_pm2", "int_ec"),
                        ("win_notyet20", "int_ec"), ("win_expired20", "int_ec")):
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


def payload(seed, n):
    """The client's payload (see the contract above)."""
    return bytes(((i * 131 + (i >> 8) * 7 + seed) ^ (seed >> 8)) & 0xFF for i in range(n))


def client_offer(client):
    """The cipher suites and groups the client offers, and what it says it is."""
    out = subprocess.run([client, "--list"], check=True, capture_output=True, text=True).stdout
    suites, groups, info = [], [], ""
    for line in out.splitlines():
        if line.startswith("INFO "):
            info = line[5:]
        if line.startswith("SUITES"):
            suites = [int(x.split(":")[1], 16) for x in line.split()[1:]]
        if line.startswith("GROUPS"):
            groups = [int(x, 16) for x in line.split()[1:]]
    return suites, groups, info


# ---------------------------------------------------------------- processes

# Every server and client this run starts: killed on any exit, SIGTERM and SIGINT included, and each
# PID recorded in <out>/pids.txt
LIVE = []
PIDS = []
PIDS_FILE = []
PROGRAMS = ("openssl", "gnutls_echo", "tlslite_echo", "nios_pump")


def track(proc, what):
    LIVE.append(proc)
    PIDS.append("%d %s" % (proc.pid, what))
    for path in PIDS_FILE:  # at once: a kill -9 of this process must not lose it
        with open(path, "a") as f:
            f.write(PIDS[-1] + "\n")
    return proc


def reap_previous(path):
    """Servers and clients a previous run in this directory left behind (it was killed with -9): each
    recorded PID that is still one of our programs is killed."""
    if not os.path.exists(path):
        return
    for ln in open(path).read().splitlines():
        try:
            pid = int(ln.split()[0])
        except (ValueError, IndexError):
            continue
        cmd = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout
        if cmd and any(p in cmd for p in PROGRAMS):
            os.kill(pid, signal.SIGKILL)
            print("REAPED %d left by an earlier run: %s" % (pid, cmd.strip()[:120]))
    os.remove(path)


def untrack(proc):
    if proc in LIVE:
        LIVE.remove(proc)


def reap():
    for p in list(LIVE):
        if p.poll() is None:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        untrack(p)


def write_pids():
    pass  # written as each process starts (track)


def on_signal(signum, frame):
    reap()
    write_pids()
    print("INTERRUPTED by signal %d: servers and client killed" % signum, flush=True)
    os._exit(128 + signum)


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
                 "untrusted": "rogue_int", "forged": "int_ec", "eku_client": "int_ec", "ku_no_ds": "int_ec",
                 "win_pm2": "int_ec", "win_notyet20": "int_ec", "win_expired20": "int_ec"}[cert]
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
        self.hash = hashlib.sha256()
        self.proc = track(subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE),
                          "openssl s_server " + name)
        self.ready = wait_listening(self.port, self.proc)
        self.relay = threading.Thread(target=self._relay, daemon=True)
        self.relay.start()

    def _relay(self):
        fin, fout = self.proc.stdout.fileno(), self.proc.stdin.fileno()
        try:
            while True:
                if self.end_after is not None and self.relayed >= self.end_after:
                    if self.end == "close":
                        time.sleep(0.3)  # s_server sends the last bytes back first
                        self.proc.stdin.close()  # -no_ign_eof: s_server ends the connection
                    elif self.end == "eof":
                        time.sleep(0.3)  # s_server sends the last bytes back first
                        self.proc.send_signal(signal.SIGKILL)  # a bare TCP close, no close_notify
                    return
                d = os.read(fin, 65536)
                if not d:
                    return
                self.relayed += len(d)
                self.hash.update(d)
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
        untrack(self.proc)
        return self.facts()

    def facts(self):
        """What s_server's trace says it SENT (ServerHello or HRR contents, tickets, key updates), and what it
        RECEIVED: the server_name in the ClientHello, and the client's alert."""
        f = {"server": "openssl", "relayed": self.relayed, "sha256": self.hash.hexdigest(), "tickets": 0, "hrr": 0,
             "version": None, "suite": None, "group": None, "keyupdates": 0, "alerts_sent": [],
             "handshake_done": False, "alert_received": None}
        try:
            lines = open(self.trace, errors="replace").read().splitlines()
        except OSError:
            return f
        sent = False
        msg = None
        in_versions = False
        sni_hex = None
        saw_client_hello = False
        for ln in lines:
            if re.match(r"\s+ClientHello, Length=", ln):
                saw_client_hello = True
            if sni_hex is not None:
                m = re.match(r"\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -])+)", ln)
                if m:
                    sni_hex += m.group(1).replace("-", " ").split()
                    continue
                f["sni"] = self._server_name(sni_hex)
                sni_hex = None
            if not sent and "extension_type=server_name(0)" in ln and "sni" not in f:
                sni_hex = []
                continue
            if not sent:
                m = re.search(r"Level=fatal\(2\), description=[\w ]+\((\d+)\)", ln)
                if m and f["alert_received"] is None:
                    f["alert_received"] = int(m.group(1))
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
        if saw_client_hello and "sni" not in f:
            f["sni"] = ""  # a ClientHello without server_name
        f["trace_lines"] = len(lines)
        return f

    @staticmethod
    def _server_name(hexbytes):
        # ServerNameList: length(2), then entries: type(1), length(2), name
        b = bytes(int(x, 16) for x in hexbytes)
        if len(b) >= 5 and b[2] == 0:
            n = int.from_bytes(b[3:5], "big")
            return b[5:5 + n].decode(errors="replace")
        return "?"


class GnuTLSServer:
    KIND = "gnutls"

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
        self.proc = track(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
                          "gnutls_echo " + name)
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
        untrack(self.proc)
        return self.facts()

    def facts(self):
        f = {"server": self.KIND, "tickets": 0, "hrr": 0, "version": None, "suite": None, "group": None,
             "keyupdates": 0, "received": 0, "handshake_done": False, "alert_received": None}
        for ln in open(self.log).read().splitlines():
            if ln.startswith("SERVER_NEGOTIATED"):
                kv = dict(x.split("=", 1) for x in ln.split()[1:])
                f.update(version=kv["version"], suite=kv["suite"], group=kv["group"],
                         hrr=int(kv["hrr"]) if kv["hrr"].isdigit() else None)
                if "sni" in kv:
                    f["sni"] = "" if kv["sni"] == "-" else kv["sni"]
                f["handshake_done"] = True
            if ln.startswith("SERVER_SNI "):
                v = ln.split(" ", 1)[1]
                f["sni"] = "" if v == "-" else v
            if ln.startswith("SERVER_ALERT_RECEIVED "):
                f["alert_received"] = int(ln.split()[1])
            m = re.search(r"TLSRemoteAlert\(Alert\(level=2, description=(\d+)\)\)", ln)
            if m:
                f["alert_received"] = int(m.group(1))
            if ln.startswith("SERVER_DONE"):
                head, _, end = ln.partition(" end=")  # the end may be an error message with spaces
                kv = dict(x.split("=", 1) for x in head.split()[1:])
                kv["end"] = end
                f.update(tickets=int(kv["tickets_sent"]), keyupdates=int(kv["keyupdates_sent"]),
                         received=int(kv["received"]), relayed=int(kv["echoed"]), sha256=kv.get("sha256"),
                         end=kv["end"])
            if ln.startswith("SERVER_HANDSHAKE_FAILED"):
                f["handshake_error"] = ln.split(" ", 1)[1]
        return f


class TLSLiteServer(GnuTLSServer):
    """tlslite_echo.py: tlslite-ng, pure Python; it can break the protocol in one chosen place."""
    KIND = "tlslite"

    def __init__(self, python, pki, out, name, cert="leaf_ec", tickets=0, brk=None, empty=0, empty_where="before"):
        self.port = free_port()
        self.log = os.path.join(out, name + ".server.log")
        key = {"leaf_rsa": "leaf_rsa"}.get(cert, "leaf_ec")
        cmd = [python, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tlslite_echo.py"),
               "--port", str(self.port), "--cert", os.path.join(pki, "full_%s.pem" % cert),
               "--key", os.path.join(pki, key + ".key"), "--tickets", str(tickets)]
        if brk:
            cmd += ["--break=" + brk]
        if empty:
            cmd += ["--empty", str(empty), "--empty-where", empty_where]
        self.cmd = cmd
        self.logf = open(self.log, "w")
        self.proc = track(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
                          "tlslite_echo " + name)
        first = self.proc.stdout.readline()
        self.logf.write(first)
        self.ready = first.startswith("SERVER_LISTENING")


class TamperProxy:
    """Between the client and a server: changes the server's bytes, one record chosen by its position."""

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


HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


class HRRPeer:
    """Raw records, no TLS library: answers the ClientHello with a HelloRetryRequest that selects a group
    chosen from what the client ADVERTISED (RFC 8446 section 4.1.4), and logs what the client does next."""

    ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 80: "internal_error", 50: "decode_error",
              70: "protocol_version", 10: "unexpected_message"}

    def __init__(self, out, name, select):
        # "unoffered", "share" (the group of the key share sent), "offered", or "tls12": answer with a
        # TLS 1.2 ServerHello instead, which a TLS 1.3-only client must refuse itself
        self.select = select
        self.log = os.path.join(out, name + ".server.log")
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.ready = True
        self.cmd = ["HRRPeer", select]
        self.f = {"server": "hrr", "received": 0, "after_hrr": None}
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    @staticmethod
    def _record(c):
        h = b""
        while len(h) < 5:
            d = c.recv(5 - len(h))
            if not d:
                return None
            h += d
        n = struct.unpack(">H", h[3:5])[0]
        b = b""
        while len(b) < n:
            d = c.recv(n - len(b))
            if not d:
                return None
            b += d
        return h[0], b

    @staticmethod
    def _client_hello(body):
        p = 2 + 32
        sid = body[p + 1:p + 1 + body[p]]
        p += 1 + body[p]
        p += 2 + struct.unpack(">H", body[p:p + 2])[0]
        p += 1 + body[p]
        end = p + 2 + struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        groups, shares = [], []
        sni = None
        while p < end:
            t, ln = struct.unpack(">HH", body[p:p + 4])
            d = body[p + 4:p + 4 + ln]
            if t == 0 and len(d) >= 5 and d[2] == 0:
                sni = d[5:5 + int.from_bytes(d[3:5], "big")].decode(errors="replace")
            if t == 10:
                groups = [struct.unpack(">H", d[2 + i:4 + i])[0] for i in range(0, struct.unpack(">H", d[:2])[0], 2)]
            if t == 51:
                q = 2
                while q < len(d):
                    g, kl = struct.unpack(">HH", d[q:q + 4])
                    shares.append(g)
                    q += 4 + kl
            p += 4 + ln
        return sid, groups, shares, sni

    def _run(self):
        f = self.f
        self.ls.settimeout(30)
        try:
            c, _ = self.ls.accept()
        except OSError:
            f["after_hrr"] = "no connection"
            self.ls.close()
            return
        c.settimeout(10)
        try:
            t, b = self._record(c)
            sid, groups, shares, sni = self._client_hello(b[4:])
            f["sni"] = sni or ""
            f["advertised"], f["shares"] = groups, shares
            if self.select == "tls12":
                # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, no supported_versions: a TLS 1.2 server's answer
                f["selected"] = 0
                body = struct.pack(">H", 0x0303) + os.urandom(32) + bytes([len(sid)]) + sid + \
                    struct.pack(">HB", 0xc02b, 0) + struct.pack(">H", 0)
                msg = bytes([2]) + len(body).to_bytes(3, "big") + body
                c.sendall(bytes([22, 3, 3]) + struct.pack(">H", len(msg)) + msg)
                self._after(c, f)
                return
            if self.select == "unoffered":
                # x448, ffdhe2048, secp384r1, a GREASE value: the first the client did not advertise
                g = next(x for x in (0x001e, 0x0100, 0x0018, 0x0a0a) if x not in groups)
            elif self.select == "share":
                g = shares[0]
            else:
                g = next(x for x in groups if x not in shares)
            f["selected"] = g
            ext = struct.pack(">HHH", 43, 2, 0x0304) + struct.pack(">HHH", 51, 2, g)
            body = struct.pack(">H", 0x0303) + HRR_RANDOM + bytes([len(sid)]) + sid + struct.pack(">HB", 0x1301, 0) + \
                struct.pack(">H", len(ext)) + ext
            msg = bytes([2]) + len(body).to_bytes(3, "big") + body
            c.sendall(bytes([22, 3, 3]) + struct.pack(">H", len(msg)) + msg)
            self._after(c, f)
        except (OSError, TypeError, StopIteration) as e:
            f["after_hrr"] = f["after_hrr"] or "error:%r" % e
        finally:
            c.close()
            self.ls.close()

    def _after(self, c, f):
        """What the client sends back: an alert, a second ClientHello, or nothing."""
        while True:
            r = self._record(c)
            if r is None:
                f["after_hrr"] = "eof"
                break
            t, b = r
            if t == 20:
                continue  # the compatibility-mode ChangeCipherSpec
            if t == 21:
                f["after_hrr"] = "alert:" + self.ALERTS.get(b[1], str(b[1]))
                f["alert_received"] = b[1]
            elif t == 22 and b[0] == 1:
                f["after_hrr"] = "client_hello2"
                f["shares2"] = self._client_hello(b[4:])[2]
            else:
                f["after_hrr"] = "record:%d" % t
            break

    def stop(self):
        self.t.join(timeout=15)
        with open(self.log, "w") as fh:
            fh.write(repr(self.f) + "\n")
        return self.f


# ---------------------------------------------------------------- cases

# Known failures of the client's TLS library, recorded rather than hidden. Each names the library, the
# versions it applies to (below the given one; None: every version so far), what it is, and the exact
# signature of the failure. The case is then printed as that kind (DEVIATION, KNOWN-VULNERABLE or XFAIL)
# and listed on the TLS_INTEROP_RECORDED line, but only when the failure matches the signature: any
# other failure is a FAIL. Once a library in range gets the case right, the run FAILS with "remove this
# entry", so none outlives its cause.
def _sig_deviation_pkcs1(res, facts):
    return res.get("outcome") == "ECHO_OK" and res.get("echo_ok") == "1"


def _sig_hrr_unoffered(res, facts):
    return res.get("outcome") == "FAILED" and res.get("esp_err") == "-0x6e00" and facts.get("after_hrr") == "eof"


def _sig_keyupdate(res, facts):
    # Fails on the KeyUpdate; what came before arrived intact (compared byte by byte as it came, and the
    # FAILED step's plaintext withheld, as the Ultimate does); the server did send exactly one KeyUpdate
    return res.get("outcome") == "FAILED" and res.get("esp_err") == "-0x7700" and \
        int(res.get("echo_received", "0")) > 0 and facts.get("keyupdates") == 1 and \
        res.get("tickets_taken") == str(facts.get("tickets"))


def _sig_empty4(res, facts):
    # Before any echo arrived, and with bad_record_mac sent to the server
    return res.get("outcome") == "FAILED" and res.get("esp_err") == "-0x7180" and \
        res.get("echo_received") == "0" and facts.get("alert_received") == BAD_RECORD_MAC


KNOWN = {
    "tlslite/mustfail/certverify_rsa_pkcs1_sha256": (
        "Mbed TLS", None, "DEVIATION", _sig_deviation_pkcs1, "the handshake and the echo succeed",
        "RFC 8446 section 4.4.3: \"RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether "
        "RSASSA-PKCS1-v1_5 algorithms appear in signature_algorithms\". mbedTLS accepts an rsa_pkcs1_sha256 "
        "CertificateVerify: library/ssl_tls13_generic.c checks only mbedtls_ssl_sig_alg_is_offered() "
        "(line 260 at 72aa6873, 309 at 2b96dd8e); mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported() "
        "is called on the signing side only (1063 / 1001). OpenSSL 3.6.2 s_client rejects the same server "
        "(tls12_check_peer_sigalg: wrong signature type). Low severity: the server must hold the key."),
    "raw/hrr/unoffered_group": (
        "Mbed TLS", (3, 6, 7), "KNOWN-VULNERABLE", _sig_hrr_unoffered,
        "FAILED -0x6e00 and the peer sees no alert (EOF)",
        "CVE-2026-25832, fixed in mbedTLS 3.6.7: a TLS 1.3 client accepts a HelloRetryRequest for a group "
        "it did not advertise. Here it then fails on its own (no key share for the group) without the "
        "illegal_parameter alert RFC 8446 section 4.1.4 requires."),
    "gnutls/keyupdate/after1024": (
        "Mbed TLS", (3, 6, 8), "XFAIL", _sig_keyupdate,
        "FAILED -0x7700 after some echo, one KeyUpdate sent, every ticket taken",
        "mbedTLS 3.6.0-3.6.7 have no KeyUpdate: ssl_tls13_handle_hs_message_post_handshake() returns "
        "MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE for anything but a NewSessionTicket (ssl_msg.c:5594-5610 at "
        "72aa6873, 5789-5820 at 2b96dd8e). The session fails; the bytes before the KeyUpdate that the "
        "Ultimate took are intact, and the FAILED step's own plaintext is withheld. Gated to below 3.6.8: "
        "a later version must be checked again."),
    "tlslite/empty/4x/before": (
        "Mbed TLS", None, "XFAIL", _sig_empty4, "FAILED -0x7180 before any echo, bad_record_mac sent",
        "mbedTLS takes at most 3 empty records in a row (ssl_msg.c:4079-4092 at 72aa6873: nb_zero > 3 is "
        "MBEDTLS_ERR_SSL_INVALID_MAC), a limit against a flood of them. RFC 8446 section 5.1 allows empty "
        "application data records without a number."),
}


def known_entry(name, info):
    k = KNOWN.get(name)
    if not k:
        return None
    lib, below, kind, sig, sig_text, text = k
    m = re.search(re.escape(lib) + r" (\d+)\.(\d+)\.(\d+)", info)
    if not m:
        return None
    if below and tuple(int(x) for x in m.groups()) >= below:
        return None
    return kind, sig, sig_text, text


class Case:
    def __init__(self, name, server, sargs, client, expect, proxy=None):
        self.name, self.server, self.sargs, self.client, self.expect, self.proxy = \
            name, server, sargs, client, expect, proxy


PAYLOADS = [1, 511, 512, 1024, 3000, 16500]
# (label, plaintext per write, ciphertext per read: 0 is what the step has room for, as the Nios reads)
CHUNKINGS = [("pt512", 512, 0), ("pt1024", 1024, 0), ("pt512-ct1", 512, 1), ("pt512-ct1500", 512, 1500)]
TICKETS = [0, 1, 2, 8]

# TLS alert descriptions (RFC 8446 section 6)
BAD_RECORD_MAC, UNEXPECTED_MESSAGE, BAD_CERTIFICATE, CERTIFICATE_EXPIRED, CERTIFICATE_UNKNOWN = 20, 10, 42, 45, 46
ILLEGAL_PARAMETER, UNKNOWN_CA, DECRYPT_ERROR, PROTOCOL_VERSION = 47, 48, 51, 70
UNSUPPORTED_CERTIFICATE = 43

TWENTY_YEARS = 20 * 365 * 86400


def mbedtls_version(info):
    m = re.search(r"Mbed TLS (\d+)\.(\d+)\.(\d+)", info)
    return tuple(int(x) for x in m.groups()) if m else None


def by_version(info, v360, v367):
    """A value that mbedTLS changed between 3.6.0 and 3.6.7: the one of the client's version, both
    where the versions in between (not run) or another library could give either."""
    v = mbedtls_version(info)
    if v and v <= (3, 6, 0):
        return v360
    if v and v >= (3, 6, 7):
        return v367
    return (v360, v367)


def matrix(suites, groups, info=""):
    cases = []
    # A usage (KU/EKU) failure: certificate_unknown from mbedTLS 3.6.0, unsupported_certificate from 3.6.7
    usage_alert = by_version(info, CERTIFICATE_UNKNOWN, UNSUPPORTED_CERTIFICATE)
    first, second = GROUPS[groups[0]], "secp256r1"
    grouplist = [(first, 0), (second, 0 if first == second else 1)]
    for srv in ("openssl", "gnutls"):
        default_tickets = 2
        # Handshake parameters: every suite the client offers x groups (and an HRR) x both chains
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
        # Many tickets, as the client reads them
        for t in (4, 5, 10, 40):
            for n in (1, 100, 3000):
                cases.append(Case("%s/tickets-many/tickets%d/%dB" % (srv, t, n), srv, dict(tickets=t),
                                  dict(echo=n, pt=512, ct=0), dict(ok=True, tickets=t)))
        # A burst: the tickets already in the socket when the first write goes out
        for t in (2, 4, 5, 8):
            for n in (1, 3000):
                cases.append(Case("%s/burst/tickets%d/%dB" % (srv, t, n), srv, dict(tickets=t),
                                  dict(echo=n, pt=512, ct=0, settle=100), dict(ok=True, tickets=t)))
        # Scripted: the echo's one write goes out with no ciphertext; 150 ms later the next read takes
        # the start of the server's flight (one byte, or with more than five tickets all but about the
        # last five, a ticket record being about 234-250 bytes from both servers), and the reads after it
        # the rest (at most a step, 1536 bytes, each): tickets and the echo together, nothing to send
        for t in (1, 2, 4, 5, 8, 10, 40):
            first = 1 if t <= 5 else (t - 5) * 250 - 50
            for n in (1, 100):
                cases.append(Case("%s/burst-after-write/tickets%d/%dB" % (srv, t, n), srv, dict(tickets=t),
                                  dict(echo=n, pt=512, ct=0, settle=150, settle_at=1, caps="0,%d" % first),
                                  dict(ok=True, tickets=t)))
        # Endings. PEER_CLOSED is the Ultimate's own finding (its socket read 0): the engine is never told.
        cases.append(Case("%s/end/close_notify" % srv, srv, dict(tickets=2, end_after=3000, end="close"),
                          dict(echo=3000, pt=512, ct=0, after="close"), dict(ok=True, outcome="CLOSED", tickets=2)))
        cases.append(Case("%s/end/bare_tcp_close" % srv, srv, dict(tickets=2, end_after=3000, end="eof"),
                          dict(echo=3000, pt=512, ct=0, after="eof"), dict(ok=True, outcome="PEER_CLOSED", tickets=2)))
        # Must fail, by the client's own check: nothing may come through, the engine's error is the one
        # that check gives, and (from s_server, which can read it) the client's alert is the one mbedTLS
        # maps the failure to (ssl_tls13_generic.c:757-779 at 72aa6873). GnuTLS cannot read these alerts:
        # the client sends them before its handshake keys are on (RFC 8446 appendix A.1), and gnutls-serv
        # reports "Decryption has failed".
        bad = [("hostname_mismatch", dict(), dict(sni="wrong.example.net"), "-0x2700", BAD_CERTIFICATE),
               ("untrusted_root", dict(cert="untrusted"), {}, "-0x2700", UNKNOWN_CA),
               ("expired", dict(cert="expired"), {}, "-0x2700", CERTIFICATE_EXPIRED),
               ("not_yet_valid", dict(cert="notyet"), {}, "-0x2700", CERTIFICATE_UNKNOWN),
               ("forged_signature", dict(cert="forged"), {}, "-0x2700", UNKNOWN_CA),
               ("eku_client_only", dict(cert="eku_client"), {}, "-0x7a00", usage_alert),
               ("not_yet_valid_20_days", dict(cert="win_notyet20"), {}, "-0x2700", CERTIFICATE_UNKNOWN),
               ("expired_20_days_ago", dict(cert="win_expired20"), {}, "-0x2700", CERTIFICATE_EXPIRED)]
        if srv == "openssl":
            bad.append(("ku_no_digital_signature", dict(cert="ku_no_ds"), {}, "-0x7a00", usage_alert))
        if srv == "gnutls":
            bad.append(("key_mismatch", dict(key="other"), {}, "-0x6e00", None))
        for label, sa, ca, err, alert in bad:
            cases.append(Case("%s/mustfail/%s" % (srv, label), srv, dict(tickets=2, **sa), dict(echo=3000, **ca),
                              dict(ok=False, err=err, alert=alert if srv == "openssl" else None)))
        # The device's clock (the Ultimate's unix_time, through the engine's settimeofday) is what the
        # certificates are checked against: 20 years ahead, the good chain has expired
        cases.append(Case("%s/clock/ahead_20_years" % srv, srv, dict(tickets=2),
                          dict(echo=100, clock="+%d" % TWENTY_YEARS),
                          dict(ok=False, err="-0x2700", alert=CERTIFICATE_EXPIRED if srv == "openssl" else None)))
        # Refused by the SERVER, not by the client's check: the client only reads the server's alert.
        # (TLS 1.2 is not even compiled into the client; raw/tls12_serverhello tests the client's side.)
        refused = [("tls12_only", dict(tls12=True))]
        if srv == "gnutls":
            refused.append(("ku_no_digital_signature", dict(cert="ku_no_ds")))  # gnutls-serv will not use it
        for label, sa in refused:
            cases.append(Case("%s/server-refuses/%s" % (srv, label), srv, dict(tickets=2, **sa), dict(echo=3000),
                              dict(ok=False, err="-0x7780", refused=True)))
    # No clock at all: OPEN refuses to verify (reason NO_TIME), before any byte goes out; and no entropy:
    # OPEN refuses (reason NO_ENTROPY)
    cases.append(Case("openssl/clock/none", "openssl", dict(tickets=2), dict(echo=100, clock="none"),
                      dict(ok=False, open_refused=True, reason=2)))
    cases.append(Case("openssl/refused/no_entropy", "openssl", dict(tickets=2), dict(echo=100, no_entropy=1),
                      dict(ok=False, open_refused=True, reason=1)))
    # A leaf valid only within 2 days of now: it passes only if the device's clock is the Ultimate's, as
    # the certificate check sees it (not as the module reports it). Also after an earlier OPEN set the
    # clock 30 days ahead: the second OPEN's clock must count. And 30 days ahead, it must fail.
    for srv in ("openssl", "gnutls"):
        cases.append(Case("%s/clock/window_2_days" % srv, srv, dict(tickets=2, cert="win_pm2"),
                          dict(echo=100), dict(ok=True, tickets=2)))
        cases.append(Case("%s/clock/window_2_days_after_open_30_days_ahead" % srv, srv,
                          dict(tickets=2, cert="win_pm2"), dict(echo=100, pre_open=30 * 86400),
                          dict(ok=True, tickets=2)))
        cases.append(Case("%s/clock/window_2_days_30_days_ahead" % srv, srv, dict(tickets=2, cert="win_pm2"),
                          dict(echo=100, clock="+%d" % (30 * 86400)),
                          dict(ok=False, err="-0x2700", alert=CERTIFICATE_EXPIRED if srv == "openssl" else None)))
    # KeyUpdate from the server, mid-stream (GnuTLS; s_server -quiet cannot be told to). A positive case:
    # a client that implements KeyUpdate passes it; mbedTLS 3.6 is an XFAIL in KNOWN.
    cases.append(Case("gnutls/keyupdate/after1024", "gnutls", dict(tickets=2, keyupdate_after=1024),
                      dict(echo=3000, pt=512, ct=0), dict(ok=True, tickets=2, keyupdates=1)))
    # Tampering on the wire, by the server's record number: 0 ServerHello, 1 ChangeCipherSpec, then the
    # encrypted EncryptedExtensions 2, Certificate 3, CertificateVerify 4, Finished 5 (s_server sends one
    # record per message, as its -trace shows). A flip inside an encrypted record tests the record
    # protection (bad_record_mac), not the message in it: tlslite/mustfail/* break the messages themselves.
    for label, mode, idx, err, alert in (
            ("serverhello_flip", "flip", 0, "-0x6600", ILLEGAL_PARAMETER),
            # the rest of the message is missing: DECODE_ERROR on 3.6.0; 3.6.7 reassembles handshake messages
            # across records (3.6.3) and then meets the leftover bytes as a record: INVALID_RECORD
            ("serverhello_shortened", "shorten", 0, by_version(info, "-0x7080", "-0x7200"), None),
            ("record_flip_certificate", "flip", 3, "-0x7180", BAD_RECORD_MAC),
            ("record_flip_certificateverify", "flip", 4, "-0x7180", BAD_RECORD_MAC),
            ("record_flip_finished", "flip", 5, "-0x7180", BAD_RECORD_MAC)):
        cases.append(Case("openssl/tamper/%s" % label, "openssl", dict(tickets=2), dict(echo=3000),
                          dict(ok=False, err=err, alert=alert), proxy=(mode, idx)))
    # Cut off inside the ServerHello: the Ultimate sees the TCP close (PEER_CLOSED); the engine is not told
    cases.append(Case("openssl/tamper/serverhello_truncated", "openssl", dict(tickets=2), dict(echo=3000),
                      dict(ok=False, peer_closed=True), proxy=("truncate", 0)))
    # A record of echo data damaged late in a long echo, when steps are full of plaintext: the session
    # must fail with bad_record_mac, and that alert must still reach the server (TLS_ALERT_ROOM). What
    # came before is intact; the failing step's plaintext is withheld.
    for idx in (14, 20, 26):
        cases.append(Case("openssl/tamper-late/appdata_flip_record%d" % idx, "openssl", dict(tickets=2),
                          dict(echo=16500, pt=512, ct=0),
                          dict(ok=False, late=True, err="-0x7180", alert=BAD_RECORD_MAC), proxy=("flip", idx)))
    # HelloRetryRequest from a raw peer (RFC 8446 section 4.1.4): a group the client did not advertise
    # (CVE-2026-25832, fixed in mbedTLS 3.6.7), or the group of the key share it already sent, must be
    # answered with an illegal_parameter alert; an advertised group with a second ClientHello
    for label, select in (("unoffered_group", "unoffered"), ("group_of_sent_share", "share")):
        cases.append(Case("raw/hrr/%s" % label, "hrr", dict(select=select), dict(echo=100),
                          dict(ok=False, after_hrr="alert:illegal_parameter")))
    cases.append(Case("raw/hrr/advertised_group", "hrr", dict(select="offered"), dict(echo=100),
                      dict(hrr_accept=True)))
    # A TLS 1.2 ServerHello to the TLS 1.3-only client: the client itself must refuse it with an alert
    cases.append(Case("raw/tls12_serverhello", "hrr", dict(select="tls12"), dict(echo=100),
                      dict(ok=False, after_hrr="alert:*")))
    # tlslite-ng: a third implementation, first as it is, then broken in one place each
    for cert in ("leaf_ec", "leaf_rsa"):
        for t, n, pt, ct in ((2, 3000, 512, 0), (2, 16500, 512, 0), (0, 1, 512, 1), (1, 1024, 1024, 0)):
            cases.append(Case("tlslite/echo/%s/tickets%d/%dB/pt%d-ct%d" % (cert[5:], t, n, pt, ct), "tlslite",
                              dict(cert=cert, tickets=t), dict(echo=n, pt=pt, ct=ct), dict(ok=True, tickets=t)))
    # Empty application data records (RFC 8446 section 5.1), 1 to 4 in a row, before or after each piece
    # of the echo: data before them and after them must arrive, and the session stay open
    for k in (1, 2, 3, 4):
        for where in ("before", "after"):
            if k == 4 and where == "after":
                continue
            cases.append(Case("tlslite/empty/%dx/%s" % (k, where), "tlslite",
                              dict(tickets=2, empty=k, empty_where=where), dict(echo=3000, pt=512, ct=0),
                              dict(ok=True, tickets=2)))
    # The server's Finished MAC is wrong; its CertificateVerify is signed over the client's context string,
    # or with a scheme the client did not offer; or with RSASSA-PKCS1-v1_5, which the client offers for
    # certificates only (RFC 8446 section 4.4.3: "RSA signatures MUST use an RSASSA-PSS algorithm")
    for label, cert, brk in (("finished_wrong", "leaf_ec", "finished"),
                             ("certverify_client_context", "leaf_ec", "cv-context"),
                             ("certverify_not_offered_ecdsa_sha1", "leaf_ec", "cv-scheme:ecdsa_sha1"),
                             ("certverify_not_offered_rsa_pkcs1_sha1", "leaf_rsa", "cv-scheme:rsa_pkcs1_sha1"),
                             ("certverify_rsa_pkcs1_sha256", "leaf_rsa", "cv-scheme:rsa_pkcs1_sha256")):
        cases.append(Case("tlslite/mustfail/%s" % label, "tlslite", dict(cert=cert, brk=brk), dict(echo=100),
                          dict(ok=False, err="-0x6e00", alert=DECRYPT_ERROR)))
    return cases


def run_case(c, a, out, info=""):
    base = re.sub(r"[^\w.-]", "_", c.name)
    if c.server == "openssl":
        srv = OpenSSLServer(a.openssl, a.pki, out, base, **c.sargs)
    elif c.server == "gnutls":
        srv = GnuTLSServer(a.gnutls, a.pki, out, base, **c.sargs)
    elif c.server == "tlslite":
        srv = TLSLiteServer(a.tlslite_python, a.pki, out, base, **c.sargs)
    else:
        srv = HRRPeer(out, base, **c.sargs)
    if not srv.ready:
        srv.stop()
        return "FAIL", "server did not start: %s" % " ".join(srv.cmd)
    port = srv.port
    proxy = None
    if c.proxy:
        proxy = TamperProxy(port, *c.proxy)
        port = proxy.port
    p = c.client
    seed = zlib.crc32(c.name.encode())
    cmd = [a.client, "--port", str(port), "--sni", p.get("sni", "localhost"), "--echo", str(p.get("echo", 0)),
           "--pt-chunk", str(p.get("pt", 512)), "--ct-chunk", str(p.get("ct", 0)), "--after", p.get("after", "none"),
           "--seed", str(seed), "--settle-ms", str(p.get("settle", 0)), "--settle-at", str(p.get("settle_at", 0))]
    cmd += (["--ct-caps", p["caps"]] if "caps" in p else [])
    cmd += (["--clock-offset", p["clock"]] if "clock" in p else [])
    cmd += (["--pre-open-offset", str(p["pre_open"])] if "pre_open" in p else [])
    cmd += (["--no-entropy", "1"] if p.get("no_entropy") else []) + (a.client_arg or [])
    proc = track(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), "client " + base)
    try:
        out_, err = proc.communicate(timeout=60)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out_, err = proc.communicate()
        rc = -1
    untrack(proc)
    facts = srv.stop()
    with open(os.path.join(out, base + ".client.log"), "w") as f:
        f.write(" ".join(cmd) + "\n" + out_ + err)
    res = {}
    for ln in out_.splitlines():
        if ln.startswith("RESULT "):
            res = dict(re.findall(r"(\w+)=(\S*)", ln))
    verdict, detail, generic_clean = judge(c, res, facts, err, rc, proxy, seed)
    known = known_entry(c.name, info)
    if not known:
        return verdict, detail
    kind, sig, sig_text, text = known
    if verdict != "FAIL":
        return "FAIL", detail + " || the library now gets this right: remove this %s entry from KNOWN" % kind
    if generic_clean and sig(res, facts):
        return kind, detail + " || " + text
    return "FAIL", detail + " || not the recorded %s failure (%s)" % (kind, sig_text)


def as_set(v):
    return v if isinstance(v, (tuple, list)) else (v,)


def judge(c, res, facts, err, rc, proxy, seed):
    why = []
    e = c.expect
    if rc != 0 or "Sanitizer" in err or "runtime error" in err:
        why.append("client exit %d / sanitizer: %s" % (rc, err.strip().splitlines()[-1:] or ""))
    if not res:
        why.append("no RESULT line")
        return "FAIL", "; ".join(why), False
    outcome = res.get("outcome")
    echo = c.client.get("echo", 0)
    detail = "outcome=%s esp_err=%s pt_delivered=%s echo_received=%s steps=%s tickets_taken=%s" % (
        outcome, res.get("esp_err"), res.get("pt_delivered"), res.get("echo_received"), res.get("steps"),
        res.get("tickets_taken", "-"))
    if facts.get("alert_received") is not None:
        detail += " alert=%d" % facts["alert_received"]

    # Checks for every case, where the client or the server reports the fact. A failure here is never
    # excused by a KNOWN entry.
    if res.get("leaked", "0") not in ("0",):
        why.append("the client left %s allocations after the session was closed" % res["leaked"])
    if res.get("clock_ok") == "0":
        why.append("the module's clock is not the unix_time the Ultimate sent")
    # The module let the session go by itself (FAILED, CLOSED) or on the Ultimate's CLOSE: the table
    # is empty, STATS for it says NOT_FOUND, and PSA holds no key
    if res.get("sessions_open", "0") != "0":
        why.append("the module still holds %s session(s) at the end" % res["sessions_open"])
    if res.get("stats_after", "0x0000") not in ("0x0000", "0x0105"):
        why.append("STATS for the ended session gave %s, not NOT_FOUND" % res["stats_after"])
    if res.get("psa_keys", "0") not in ("0", "-1"):
        why.append("PSA still holds %s key(s) at the end" % res["psa_keys"])
    want_sni = c.client.get("sni", "localhost")
    # (A server that refuses early, gnutls-serv on its own certificate, may not have stored the name)
    if "sni" in facts and facts["sni"] != want_sni and not e.get("open_refused") and not e.get("refused"):
        why.append("server_name at the server %r, want %r" % (facts["sni"], want_sni))
    if facts.get("sha256") and isinstance(facts.get("received", facts.get("relayed")), int):
        got = facts.get("relayed") if facts.get("server") == "openssl" else facts.get("received")
        if hashlib.sha256(payload(seed, got)).hexdigest() != facts["sha256"]:
            why.append("the %d bytes the server received are not the payload's first %d" % (got, got))
    if outcome == "FAILED" and res.get("esp_err") == "-0x7780" and "-0x7780" not in as_set(e.get("err")):
        why.append("the client failed on the SERVER's alert (-0x7780): nothing of the client was tested")
    generic_clean = not why

    if c.server == "hrr":
        detail += " server: advertised %s, selected %s, then %s" % (
            [hex(g) for g in facts.get("advertised", [])], hex(facts.get("selected") or 0), facts.get("after_hrr"))
        if res.get("pt_delivered") != "0":
            why.append("plaintext delivered")
        if e.get("hrr_accept"):
            if facts.get("after_hrr") != "client_hello2" or facts.get("shares2") != [facts.get("selected")]:
                why.append("an HRR for an advertised group was not answered with a ClientHello for it")
        else:
            if outcome != "FAILED":
                why.append("outcome %s, want FAILED" % outcome)
            want = e["after_hrr"]
            if not (facts.get("after_hrr") == want or (want == "alert:*" and
                                                       str(facts.get("after_hrr")).startswith("alert:"))):
                why.append("server saw %s after its message, want %s" % (facts.get("after_hrr"), want))
    elif e.get("open_refused"):
        if outcome != "OPEN_FAILED" or res.get("esp_err") != "0x0103" or \
                ("open_reason" in res and res["open_reason"] != str(e["reason"])):
            why.append("outcome %s %s reason %s, want OPEN_FAILED 0x0103 reason %d" % (
                outcome, res.get("esp_err"), res.get("open_reason"), e["reason"]))
    elif e.get("ok", True):
        want = e.get("outcome", "ECHO_OK")
        if outcome != want:
            why.append("outcome %s, want %s" % (outcome, want))
        if res.get("echo_ok") != "1" or res.get("echo_received") != str(echo):
            why.append("echo not intact")
        # A killed s_server loses the end of its trace: then the echo it relayed is the witness
        killed = c.server == "openssl" and c.sargs.get("end") == "eof"
        if not facts.get("handshake_done") and not killed:
            why.append("server saw no completed handshake")
        got = facts.get("relayed") if facts.get("server") == "openssl" else facts.get("received")
        if outcome == want and got != echo:
            why.append("server received %s of the %d bytes" % (got, echo))
        if c.server == "openssl" and not killed:
            if facts.get("version") != 0x0304:
                why.append("server version %s" % facts.get("version"))
            if "suite" in e and facts.get("suite") != e["suite"]:
                why.append("server chose suite %s" % facts.get("suite"))
            if "group" in e and facts.get("group") != OPENSSL_TRACE_GROUP[e["group"]]:
                why.append("server chose group %s" % facts.get("group"))
        elif c.server in ("gnutls", "tlslite"):
            if facts.get("version") != "TLS1.3":
                why.append("server version %s" % facts.get("version"))
            if "suite" in e and not (facts.get("suite") or "").endswith(SUITES[e["suite"]][4:]):
                why.append("server chose suite %s" % facts.get("suite"))
            if "group" in e and facts.get("group") != GNUTLS_GROUP[e["group"]]:
                why.append("server chose group %s" % facts.get("group"))
        if "hrr" in e and facts.get("hrr") != e["hrr"]:
            why.append("server HRR %s, want %s" % (facts.get("hrr"), e["hrr"]))
        if "keyupdates" in e and facts.get("keyupdates") != e["keyupdates"]:
            why.append("server sent %s KeyUpdates" % facts.get("keyupdates"))
        if "tickets" in e and not killed and facts.get("tickets") != e["tickets"]:
            why.append("server sent %s tickets, want %s" % (facts.get("tickets"), e["tickets"]))
        # The client's own count, where it reports one: every ticket the server sent was taken and kept,
        # not dropped (mbedTLS 3.6.1+ drops them unless signalling is on), so the ticket paths ran
        if "tickets_taken" in res and not killed and outcome == want and isinstance(facts.get("tickets"), int) \
                and res["tickets_taken"] != str(facts["tickets"]):
            why.append("client took %s of the %s tickets the server sent" % (res["tickets_taken"], facts["tickets"]))
    else:
        if e.get("peer_closed"):
            if outcome != "PEER_CLOSED" or res.get("state") != "0":
                why.append("outcome %s state %s, want PEER_CLOSED while handshaking" % (outcome, res.get("state")))
        elif outcome != "FAILED":
            why.append("outcome %s, want FAILED" % outcome)
        if e.get("err") and outcome == "FAILED" and res.get("esp_err") not in as_set(e["err"]):
            why.append("esp_err %s, want %s" % (res.get("esp_err"), e["err"]))
        if e.get("alert") is not None and facts.get("alert_received") not in as_set(e["alert"]):
            why.append("the server received alert %s, want %s" % (facts.get("alert_received"), e["alert"]))
        if e.get("late"):
            # Data before the damage arrived intact (compared as it came); the failure came after some
            if int(res.get("echo_received", "0")) <= 0:
                why.append("nothing arrived before the damaged record")
        else:
            if res.get("pt_delivered") != "0" or res.get("echo_sent") != "0":
                why.append("plaintext moved: delivered %s, sent %s" % (res.get("pt_delivered"),
                                                                       res.get("echo_sent")))
            if facts.get("relayed", 0) or facts.get("received", 0):
                why.append("server received application data")
        if proxy and not proxy.done:
            why.append("proxy never tampered")
    if proxy:
        detail += " proxy: " + proxy.done
    if why:
        return "FAIL", detail + " || " + "; ".join(why), generic_clean
    return "PASS", detail, generic_clean


def peer_versions(a):
    v = {}
    v["openssl"] = subprocess.run([a.openssl, "version"], capture_output=True, text=True).stdout.strip()
    v["gnutls"] = subprocess.run([a.gnutls, "--version"], capture_output=True, text=True).stdout.strip()
    v["tlslite"] = subprocess.run([a.tlslite_python, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "tlslite_echo.py"), "--version"], capture_output=True, text=True).stdout.strip()
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("pki", "run"))
    ap.add_argument("--openssl", required=True)
    ap.add_argument("--pki", required=True)
    ap.add_argument("--client")
    ap.add_argument("--gnutls")
    ap.add_argument("--tlslite-python", help="a python with tlslite-ng (requirements-tlslite.txt)")
    ap.add_argument("--out")
    ap.add_argument("--only")
    ap.add_argument("--client-arg", action="append", help="passed to the client as it is (repeatable)")
    ap.add_argument("--peers", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "PEERS"),
                    help="the peer versions the matrix was made with (KEY=VALUE lines; default: PEERS here)")
    ap.add_argument("--allow-peer-drift", action="store_true", help="run although a peer's version differs")
    ap.add_argument("--label", default="", help="what was built: printed with the summary line")
    a = ap.parse_args()
    if a.what == "pki":
        make_pki(a.openssl, a.pki)
        return 0
    if not (a.client and a.gnutls and a.tlslite_python and a.out):
        ap.error("run needs --client, --gnutls, --tlslite-python and --out")
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    os.makedirs(a.out, exist_ok=True)
    reap_previous(os.path.join(a.out, "pids.txt"))
    PIDS_FILE.append(os.path.join(a.out, "pids.txt"))
    suites, groups, info = client_offer(a.client)
    versions = peer_versions(a)
    print("PEERS openssl: %s | gnutls: %s | %s | raw peer: interop.py" % (
        versions["openssl"], versions["gnutls"], versions["tlslite"]))
    drift = []
    if a.peers:
        for ln in open(a.peers):
            ln = ln.split("#", 1)[0].strip()
            if "=" in ln:
                k, v = ln.split("=", 1)
                if versions.get(k.strip()) != v.strip():
                    drift.append("%s is %r, PEERS says %r" % (k.strip(), versions.get(k.strip()), v.strip()))
    for d in drift:
        print("PEER_DRIFT %s" % d)
    if drift and not a.allow_peer_drift:
        print("TLS_INTEROP FAIL 0/0 (a peer differs from %s; PEER_DRIFT=1 runs anyway)" % a.peers)
        return 2
    print("CLIENT %s %s: %s" % (a.client, " ".join(a.client_arg or []), info))
    print("CLIENT offers suites %s; groups %s" % (
        ", ".join(SUITES.get(x, hex(x)) for x in suites), ", ".join(GROUPS.get(g, hex(g)) for g in groups)))
    cases = matrix(suites, groups, info)
    if a.only:
        try:
            cases = [c for c in cases if re.search(a.only, c.name)]
        except re.error as err:
            print("TLS_INTEROP FAIL 0/0 (--only %r is not a regular expression: %s)" % (a.only, err))
            return 2
    if not cases:
        print("TLS_INTEROP FAIL 0/0 (no case matches --only %r)" % a.only)
        return 2
    counts = {"PASS": 0, "XFAIL": 0, "DEVIATION": 0, "KNOWN-VULNERABLE": 0, "FAIL": 0}
    recorded = []
    t0 = time.time()
    try:
        for c in cases:
            verdict, detail = run_case(c, a, a.out, info)
            counts[verdict] += 1
            if verdict in ("DEVIATION", "KNOWN-VULNERABLE", "XFAIL"):
                recorded.append("%s %s" % (verdict, c.name))
            print("%s %s %s" % (verdict, c.name, detail), flush=True)
    finally:
        reap()
        write_pids()
    good = len(cases) - counts["FAIL"]
    print("elapsed %.1f s; %d PASS, %d FAIL" % (time.time() - t0, counts["PASS"], counts["FAIL"]))
    print("TLS_INTEROP_RECORDED %d xfail, %d deviation, %d known-vulnerable: %s" % (
        counts["XFAIL"], counts["DEVIATION"], counts["KNOWN-VULNERABLE"], "; ".join(recorded) or "none"))
    print("TLS_INTEROP %s %d/%d (%s%s)" % ("PASS" if good == len(cases) else "FAIL", good, len(cases),
                                         a.label or info, "; PEER DRIFT ALLOWED" if drift else ""))
    return 0 if good == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
