#!/usr/bin/env python3
"""A TLS 1.3-only echo server that logs, from its own side, what each connection negotiated.

SPIKE CODE, not for upstream. The TLS spike suite (tls_spike_test.py) runs it on
this machine and judges the device against its log, never against the device's
own report of what happened.

Why Python's ssl module rather than `openssl s_server`: s_server has no echo
mode (it relays between the socket and its own stdin) and prints its handshake
summary as free text. Python gives an echo loop and a machine-readable log in
one process. What Python 3.13 does not give is the negotiated key-exchange
group, so this server does not ask the library at all for the facts the suite
judges: it drives the TLS object through memory BIOs, sees every byte it
receives and sends, and parses the unencrypted part of the handshake itself.
The ClientHello gives the SNI and what the client offered; the ServerHello the
server actually sent gives the version, the cipher suite and the group. The
library's own version() and cipher() are logged beside them, and the two
sources must agree (`sources_agree`).

The group policy is set through OpenSSL's configuration (`Groups =` in the
system_default section), which Python's SSLContext picks up when the process
first loads OpenSSL. That is why this is a separate process, which re-executes
itself with OPENSSL_CONF set before anything loads OpenSSL. The ServerHello is
checked against the policy as well, so a policy that did not take effect is
logged as a violation rather than trusted (it happened: hashlib loads OpenSSL
first, and an in-process OPENSSL_CONF was silently ignored).

One connection at a time. One JSON line per connection, appended to --log when
the connection ends, so the reader can wait for the line to appear. The line
also says whether the client closed its end of the TCP connection (`fin`). The first
line on stdout is `LISTENING <port>`.
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

TLS13 = 0x0304
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

GROUPS = {"x25519": 0x001D, "p256": 0x0017}
GROUP_NAMES = {0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1",
               0x001E: "x448", 0x0019: "secp521r1", 0x11EC: "X25519MLKEM768"}
OPENSSL_GROUPS = {"x25519": "X25519", "p256": "P-256", "both": "X25519:P-256"}
SUITE_NAMES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
               0x1303: "TLS_CHACHA20_POLY1305_SHA256"}

MANGLE_MODES = ("none", "flip-last", "drop-last")
GROUPS_ENV = "TLS_SPIKE_SERVER_GROUPS"


def allowed_groups(mode: str) -> list[int]:
    return list(GROUPS.values()) if mode == "both" else [GROUPS[mode]]


# --------------------------------------------------------------- wire parsing --

def _u16s(data: bytes) -> list[int]:
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2)]


def _extensions(body: bytes, offset: int) -> dict[int, bytes]:
    found: dict[int, bytes] = {}
    if offset + 2 > len(body):
        return found
    end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    while offset + 4 <= end:
        kind = int.from_bytes(body[offset:offset + 2], "big")
        length = int.from_bytes(body[offset + 2:offset + 4], "big")
        found[kind] = body[offset + 4:offset + 4 + length]
        offset += 4 + length
    return found


def parse_client_hello(body: bytes) -> dict:
    offset = 2 + 32
    offset += 1 + body[offset]
    suites = _u16s(body[offset + 2:offset + 2 + int.from_bytes(body[offset:offset + 2], "big")])
    offset += 2 + int.from_bytes(body[offset:offset + 2], "big")
    offset += 1 + body[offset]
    ext = _extensions(body, offset)
    sni = None
    if 0x0000 in ext and len(ext[0x0000]) >= 5:
        name_len = int.from_bytes(ext[0x0000][3:5], "big")
        sni = ext[0x0000][5:5 + name_len].decode("ascii", "replace")
    shares = []
    if 0x0033 in ext:
        data, pos = ext[0x0033][2:], 0
        while pos + 4 <= len(data):
            shares.append(int.from_bytes(data[pos:pos + 2], "big"))
            pos += 4 + int.from_bytes(data[pos + 2:pos + 4], "big")
    return {
        "sni": sni,
        "versions": _u16s(ext[0x002B][1:]) if 0x002B in ext else [],
        "groups": _u16s(ext[0x000A][2:]) if 0x000A in ext else [],
        "key_share_groups": shares,
        "cipher_suites": suites,
        "signature_algorithms": _u16s(ext[0x000D][2:]) if 0x000D in ext else [],
        "early_data": 0x002A in ext,
    }


def parse_server_hello(body: bytes) -> dict:
    random = body[2:34]
    offset = 34
    offset += 1 + body[offset]
    suite = int.from_bytes(body[offset:offset + 2], "big")
    ext = _extensions(body, offset + 3)
    version = int.from_bytes(ext[0x002B][:2], "big") if 0x002B in ext else None
    group = int.from_bytes(ext[0x0033][:2], "big") if 0x0033 in ext else None
    return {"hrr": random == HRR_RANDOM, "version": version, "cipher_suite": suite,
            "group": group}


class Direction:
    """One direction of the TLS byte stream, parsed as far as it is plaintext.

    In TLS 1.3 everything after the ServerHello is encrypted, and the record
    type of an encrypted record is always application_data (23). So the
    plaintext handshake of a direction is its type-22 records before the first
    type-23 one, and the plaintext alerts are its type-21 records before that.
    """

    def __init__(self) -> None:
        self.buffer = b""
        self.handshake = b""
        self.encrypted = False
        self.records = 0
        self.bytes = 0
        self.messages: list[tuple[int, bytes]] = []
        self.alerts: list[tuple[int, int]] = []

    def feed(self, data: bytes) -> None:
        self.bytes += len(data)
        self.buffer += data
        while len(self.buffer) >= 5:
            length = int.from_bytes(self.buffer[3:5], "big")
            if len(self.buffer) < 5 + length:
                return
            kind, fragment = self.buffer[0], self.buffer[5:5 + length]
            self.buffer = self.buffer[5 + length:]
            self.records += 1
            if kind == 23:
                self.encrypted = True
            elif kind == 22 and not self.encrypted:
                self.handshake += fragment
                self._messages()
            elif kind == 21 and not self.encrypted and len(fragment) >= 2:
                self.alerts.append((fragment[0], fragment[1]))

    def _messages(self) -> None:
        while len(self.handshake) >= 4:
            length = int.from_bytes(self.handshake[1:4], "big")
            if len(self.handshake) < 4 + length:
                return
            self.messages.append((self.handshake[0], self.handshake[4:4 + length]))
            self.handshake = self.handshake[4 + length:]


# ------------------------------------------------------------------- serving --

def openssl_conf(groups: str) -> str:
    handle, path = tempfile.mkstemp(prefix="tls-spike-", suffix=".cnf")
    with os.fdopen(handle, "w") as stream:
        stream.write("openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n"
                     "[ssl_sect]\nsystem_default = sysdef\n"
                     f"[sysdef]\nGroups = {OPENSSL_GROUPS[groups]}\n")
    return path


def wait_for_fin(conn: socket.socket, seconds: float) -> bool:
    """Whether the client closed its end of the TCP connection within `seconds`.

    A close_notify or an alert ends the TLS session, not the socket. The spec
    wants the socket closed on every exit path, and a client that leaves it
    open is only visible here: the server holds its own end open and waits.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if conn.recv(65536) == b"":
                return True
        except TimeoutError:
            continue
        except OSError:
            return True
    return False


def serve_one(ssl, context, conn: socket.socket, peer, args, number: int) -> dict:
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=True)
    c2s, s2c = Direction(), Direction()
    record: dict = {"conn": number, "peer": f"{peer[0]}:{peer[1]}", "chain": args.chain,
                    "groups_mode": args.groups, "groups_allowed": allowed_groups(args.groups),
                    "mangle": args.mangle, "expect_bytes": args.expect_bytes,
                    "accepted": time.time(), "handshake_ok": False, "error": None,
                    "close": None, "sni_callback": None}
    received = bytearray()
    echoed = bytearray()
    first_byte = None
    handshake_done = None
    established = False

    def on_sni(_obj, name, _context):
        record["sni_callback"] = name

    context.sni_callback = on_sni

    def flush() -> None:
        data = outgoing.read()
        if data:
            s2c.feed(data)
            conn.sendall(data)

    def echo(chunk: bytes) -> None:
        position = len(received) - len(chunk)
        target = (args.expect_bytes - 1) if args.expect_bytes else 0
        out = bytearray(chunk)
        if args.mangle != "none" and position <= target < position + len(chunk):
            if args.mangle == "flip-last":
                out[target - position] ^= 0x01
            else:
                del out[target - position]
            record["mangled_at"] = target
        echoed.extend(out)
        if out:
            tls.write(bytes(out))

    conn.settimeout(0.2)
    last_activity = time.monotonic()
    try:
        while True:
            try:
                data = conn.recv(65536)
            except TimeoutError:
                data = None
            except OSError as exc:
                record["close"] = f"socket error: {exc}"
                break
            if data is None:
                if time.monotonic() - last_activity > args.idle_timeout:
                    record["close"] = "idle-timeout"
                    break
                continue
            if data == b"":
                record["close"] = "eof"
                break
            # Both ends of server_handshake_ms are the moment recv() returned,
            # not the moment the TLS work on those bytes finished, so the
            # server's own processing and scheduling after the client's
            # Finished arrived are not counted.
            last_activity = time.monotonic()
            if first_byte is None:
                first_byte = last_activity
            c2s.feed(data)
            incoming.write(data)
            try:
                if not established:
                    tls.do_handshake()
                    established = True
                    handshake_done = last_activity
                    record["handshake_ok"] = True
                    record["version_api"] = tls.version()
                    record["cipher_api"] = tls.cipher()[0]
                while True:
                    chunk = tls.read(65536)
                    if not chunk:
                        # SSLObject.read answers a close_notify with b"" rather
                        # than raising; running out of data raises instead.
                        raise ssl.SSLZeroReturnError
                    received.extend(chunk)
                    echo(chunk)
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLZeroReturnError:
                record["close"] = "close_notify"
                try:
                    tls.unwrap()
                except ssl.SSLError:
                    pass
                flush()
                break
            except ssl.SSLError as exc:
                record["error"] = {"reason": exc.reason, "library": exc.library,
                                   "message": str(exc)}
                record["close"] = "tls-error"
                flush()
                break
            flush()
        record["fin"] = record["close"] == "eof" or wait_for_fin(conn, args.fin_wait)
    finally:
        conn.close()

    hellos_in = [parse_client_hello(body) for kind, body in c2s.messages if kind == 1]
    hellos_out = [parse_server_hello(body) for kind, body in s2c.messages if kind == 2]
    final = next((h for h in reversed(hellos_out) if not h["hrr"]), None)
    record["wire"] = {
        "client_hellos": hellos_in,
        "server_hellos": hellos_out,
        "client_plain_alerts": c2s.alerts,
        "server_plain_alerts": s2c.alerts,
        "client_records": c2s.records,
        "server_records": s2c.records,
    }
    record["negotiated"] = {
        "version": final["version"] if final else None,
        "cipher_suite": final["cipher_suite"] if final else None,
        "group": final["group"] if final else None,
        "hrr": any(h["hrr"] for h in hellos_out),
    }
    record["sni_wire"] = hellos_in[-1]["sni"] if hellos_in else None
    reason = (record["error"] or {}).get("reason") or ""
    record["alert_from_client"] = reason if "ALERT" in reason else None
    record["tcp_in"] = c2s.bytes
    record["tcp_out"] = s2c.bytes
    record["app_in"] = len(received)
    record["app_out"] = len(echoed)
    record["app_in_sha256"] = hashlib.sha256(received).hexdigest()
    record["app_out_sha256"] = hashlib.sha256(echoed).hexdigest()
    record["app_in_head"] = bytes(received[:32]).hex()
    record["server_handshake_ms"] = (
        round((handshake_done - first_byte) * 1000, 3) if handshake_done and first_byte else None)
    record["ended"] = time.time()
    violations = []
    if record["handshake_ok"]:
        if record["negotiated"]["version"] != TLS13:
            violations.append(f"version {record['negotiated']['version']!r} is not TLS 1.3")
        if record["negotiated"]["group"] not in record["groups_allowed"]:
            violations.append(f"group {record['negotiated']['group']!r} is outside the policy")
        api_suite = next((k for k, v in SUITE_NAMES.items() if v == record["cipher_api"]), None)
        if record["version_api"] != "TLSv1.3" or api_suite != record["negotiated"]["cipher_suite"]:
            violations.append(f"the library says {record['version_api']} "
                              f"{record['cipher_api']}, the wire says "
                              f"{record['negotiated']['version']} "
                              f"{record['negotiated']['cipher_suite']}")
    if record["sni_callback"] is not None and record["sni_callback"] != record["sni_wire"]:
        violations.append(f"SNI callback {record['sni_callback']!r} differs from the "
                          f"ClientHello's {record['sni_wire']!r}")
    record["violations"] = violations
    record["sources_agree"] = not violations
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--chain", required=True,
                        choices=("ecdsa", "rsa", "mismatch", "expired", "untrusted"))
    parser.add_argument("--groups", choices=tuple(OPENSSL_GROUPS), default="both")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log", required=True, help="JSON lines, one per connection")
    parser.add_argument("--mangle", choices=MANGLE_MODES, default="none",
                        help="corrupt the echo on purpose: flip or drop the byte at "
                             "--expect-bytes - 1 (a control for the device's echo check)")
    parser.add_argument("--expect-bytes", type=int, default=0)
    parser.add_argument("--tickets", type=int, default=2,
                        help="TLS 1.3 session tickets sent after the handshake "
                             "(2 is OpenSSL's default, which real servers send)")
    parser.add_argument("--idle-timeout", type=float, default=15.0)
    parser.add_argument("--fin-wait", type=float, default=5.0,
                        help="after the TLS session ends, how long the client has to close "
                             "its end of the TCP connection")
    args = parser.parse_args()

    # OpenSSL reads its configuration once, when the process first loads it,
    # and hashlib has already done that by now. So the policy is handed to a
    # fresh copy of this process through its environment.
    if os.environ.get(GROUPS_ENV) != args.groups:
        conf = openssl_conf(args.groups)
        env = dict(os.environ, OPENSSL_CONF=conf, **{GROUPS_ENV: args.groups})
        os.execve(sys.executable, [sys.executable, *sys.argv], env)
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = args.tickets
    chain = Path(args.pki_dir) / "chains" / args.chain
    context.load_cert_chain(chain / "chain.pem", chain / "key.pem")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(4)
    print(f"LISTENING {listener.getsockname()[1]}", flush=True)
    number = 0
    while True:
        conn, peer = listener.accept()
        number += 1
        record = serve_one(ssl, context, conn, peer, args, number)
        with open(args.log, "a", encoding="utf-8") as log:
            log.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
