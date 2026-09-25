#!/usr/bin/env python3
"""Offline check of the TLS spike oracle: the real suite against fake devices.

SPIKE CODE, not for upstream, and not a registered suite: it needs no device,
and it exists to show which broken firmwares tls_spike_test.py catches.

Each fake device is a loopback HTTP server that answers the spike route the
way a firmware might. The honest ones really are TLS 1.3 clients (Python ssl
driven through memory BIOs, so the fake counts its round trips as steps) that
connect to the suite's own echo server; the broken ones deviate in exactly one
way. The real suite runs against each fake as a child process, with
U64_REST_PORT pointing it at the fake, and the fake's verdicts are compared
with what each one must get.

    python3 tests/e2e/io/wifi/tls_spike_sim.py [--mode NAME ...] [--repeat N]
"""

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The one stanza that puts the shared library on sys.path; see tests/lib/bootstrap.py.
sys.path.insert(0, str(next(p for p in Path(__file__).resolve().parents
                            if (p / "tests" / "lib").is_dir()) / "tests" / "lib"))
import bootstrap  # noqa: E402,F401

sys.path.insert(0, bootstrap.directory("e2e", "io", "wifi"))
import tls_spike_pki as pki  # noqa: E402
from tls_spike_server import Direction, parse_server_hello  # noqa: E402

HERE = Path(__file__).resolve().parent

ROUTE = "/v1/machine:tlsspike"
READ_TIMEOUT = 3.0
STEP_DELAY = 0.03
STEP_DELAY_MS = 30

# mode -> (what it does wrong, the scenarios that must FAIL; None means the
# suite must pass). A scenario named here has to fail, and every other has to
# pass, WARN included, so a mode that fails for a reason nobody predicted is
# reported as such.
MODES = {
    "correct": ("a spec-correct device", None),
    "stock": ("stock firmware: no route, HTTP 404 with an empty body", {"f"}),
    "slow-first-put": ("the first PUT gets no answer within the suite's timeout; it must "
                       "not be re-issued", {"a"}),
    "stale-image": ("run with --expect-spike against an image that answers 404 like stock",
                    {"f"}),
    "verify-ignored": ("verify=1 is accepted and never applied",
                       {"d-mismatch", "d-untrusted", "d-expired"}),
    "fallback-retry": ("on a verification failure, silently reconnects with verification "
                       "off and reports success", {"d-mismatch", "d-untrusted", "d-expired"}),
    "fallback-reports-failed": ("reports FAILED honestly, but reconnects with verification "
                                "off behind the report and sends the echo anyway",
                                {"d-mismatch", "d-untrusted", "d-expired"}),
    "lie-group": ("reports X25519 (29) whatever the ServerHello said; a correct device "
                  "reports 0, unknown (section 10)", {"c-p256"}),
    "echo-corrupt-honest": ("flips a byte of the echo on the way in, and says so",
                            {"a", "b", "c-x25519", "c-p256", "e-verify-off"}),
    "echo-corrupt-liar": ("flips a byte of the echo on the way in, and says echo_ok anyway",
                          {"echo-flip", "echo-short"}),
    "echo-always-ok": ("never compares the echo: echo_ok is always true",
                       {"echo-flip", "echo-short"}),
    "no-close": ("sends close_notify but leaves the TCP connection open",
                 {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short", "d-mismatch",
                  "d-untrusted", "d-expired", "e-verify-off"}),
    "no-alert": ("drops the ESP32's final ciphertext, so the server never sees the alert; a "
                 "FAIL since amendment 11 F", {"d-mismatch", "d-untrusted", "d-expired"}),
    "no-test-ca": ("ca=test loads nothing: every verify-on handshake fails",
                   {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short",
                    "d-mismatch", "d-untrusted", "d-expired"}),
    "wrong-payload": ("ignores the seed and sends its own pattern: echo_ok is true, but the "
                      "server received the wrong bytes",
                      {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short",
                       "e-verify-off"}),
    "no-time-correct": ("no trusted time (time_source none): refuses verify-on at OPEN "
                        "without sending a byte, as section 9 requires",
                        {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short",
                         "d-mismatch", "d-untrusted", "d-expired"}),
    "no-time-verifies": ("reports time_source none, but verifies and runs anyway",
                         {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short",
                          "d-mismatch", "d-untrusted", "d-expired"}),
    "nios-below-esp": ("reports an ESP32 handshake_us 20 ms longer than the Nios wall clock",
                       {"a", "b", "c-x25519", "c-p256", "e-verify-off"}),
    "high-load": ("a correct device, on a host whose load average is 9 (faked): P2 must be "
                  "held back as INCONCLUSIVE", None),
    "session-leak": ("never CLOSEs its ESP32 session: sessions_open_after is 1",
                     {"a", "b", "c-x25519", "c-p256", "echo-flip", "echo-short",
                      "d-mismatch", "d-untrusted", "d-expired", "e-verify-off"}),
    "pre-a-shape": ("the route before amendment 9 A: a failed handshake reports time_source "
                    "none; now a contract FAIL, no longer called a fail-closed break",
                    {"d-mismatch", "d-untrusted", "d-expired"}),
    "orphan-before": ("an earlier run's orphan: stats_before.sessions_open and "
                      "sessions_open_after are both 1", {"a", "b", "c-x25519", "c-p256",
                                                         "echo-flip", "echo-short",
                                                         "d-mismatch", "d-untrusted",
                                                         "d-expired", "e-verify-off"}),
    "replay-hello": ("every connection after the first replays the first ClientHello",
                     {"b", "c-x25519", "c-p256", "echo-flip", "echo-short", "d-mismatch",
                      "d-untrusted", "d-expired", "e-verify-off", "a"}),
    "witness-cross-run": ("sends one fixed ClientHello per run, on its first connection; the "
                          "second run must see it in the first run's witness log", {"a"}),
    "echo-corrupt-once": ("flips a byte of the echo on its first run only, and says so; P4a "
                          "must come out OUTSIDE (amendment 12 F1)", {"a"}),
    "expect-prior-empty": ("a correct device on a 'second run' whose witness log is empty, "
                           "under --expect-prior-hellos: the suite must FAIL", set()),
    "fast-clock": ("reports handshake_ms of 1 while the server watched tens of ms; this is "
                   "a WARN by design, because a busy host inflates the server's window",
                   set()),
}


# Modes whose deviation the suite can only flag, and the scenarios that must
# carry the WARN.
# Modes whose failures must carry this text, where the set of failed scenarios
# alone cannot tell two fakes apart.
MUST_SAY = {
    "echo-corrupt-once": "P4a OUTSIDE",
    "expect-prior-empty": "--expect-prior-hellos: the witness log",
    "no-alert": "no alert reached the server",
    "orphan-before": "an earlier run left an ESP32 session open",
    "replay-hello": "entropy witness: this ClientHello random",
    "witness-cross-run": "was already sent in run",
    "slow-first-put": "no answer to PUT /v1/machine:tlsspike within",
    "stock": "this firmware has no TLS spike route",
    "stale-image": "a stale or wrong image",
    "correct": "P2a OUTSIDE",
    "high-load": "P2a INCONCLUSIVE (host load)",
    "nios-below-esp": "the Nios clock (handshake_ms=",
    "no-time-correct": "precondition: the device has no trusted time",
    "no-time-verifies": "time_source 'none' past OPEN",
    "session-leak": "sessions_open_after=1",
    "pre-a-shape": "its STATS after OPEN was not taken",
    "wrong-payload": "not the payload for seed",
}

# Modes that fail the suite without failing a scenario.
EXIT_1 = {"expect-prior-empty"}

MUST_WARN = {
    "fast-clock": {"a", "b", "c-x25519", "c-p256", "e-verify-off"},
}


def client_context(verify: bool, cafile: Path | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if cafile:
        context.load_verify_locations(cafile=str(cafile))
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class FakeSession:
    """One TLS client connection, pumped by hand the way the Nios pumps the ESP32."""

    def __init__(self, mode: str, host: str, port: int, sni: str, verify: bool,
                 cafile: Path | None) -> None:
        self.mode = mode
        self.sock = socket.create_connection((host, port), timeout=READ_TIMEOUT)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = client_context(verify, cafile).wrap_bio(
            self.incoming, self.outgoing, server_hostname=sni)
        self.s2c = Direction()
        self.steps = 0
        self.first_flight = b""

    def flush(self) -> None:
        data = self.outgoing.read()
        if data:
            if not self.first_flight:
                self.first_flight = data
            self.sock.sendall(data)

    def pull(self) -> bool:
        data = self.sock.recv(65536)
        if not data:
            return False
        # A serial link and an ESP32 are slower than loopback. Without this the
        # whole handshake takes 2 ms and timing checks with a few ms of slack
        # could not tell a made-up figure from a measured one.
        time.sleep(STEP_DELAY)
        self.s2c.feed(data)
        self.incoming.write(data)
        return True

    def handshake(self) -> str | None:
        """None when established, else the reason."""
        while True:
            self.steps += 1
            try:
                self.tls.do_handshake()
                self.flush()
                return None
            except ssl.SSLWantReadError:
                self.flush()
                if not self.pull():
                    return "eof during handshake"
            except ssl.SSLCertVerificationError as exc:
                if self.mode == "no-alert":
                    self.outgoing.read()
                else:
                    self.flush()
                return f"verify: {exc.verify_message}"
            except ssl.SSLError as exc:
                self.flush()
                return f"tls: {exc}"

    def negotiated(self) -> dict:
        hellos = [parse_server_hello(body) for kind, body in self.s2c.messages if kind == 2]
        final = next((h for h in reversed(hellos) if not h["hrr"]), {})
        return final

    def echo(self, payload: bytes) -> bytes:
        self.tls.write(payload)
        self.flush()
        got = b""
        try:
            while len(got) < len(payload):
                try:
                    got += self.tls.read(65536)
                    continue
                except ssl.SSLWantReadError:
                    pass
                self.steps += 1
                if not self.pull():
                    break
        except (TimeoutError, OSError):
            pass
        return got

    def close(self) -> None:
        try:
            self.tls.unwrap()
        except ssl.SSLError:
            pass
        try:
            self.flush()
        except OSError:
            pass
        if self.mode == "no-close":
            LEAKED.append(self.sock)
            return
        self.sock.close()


LEAKED: list[socket.socket] = []
# The replay fakes' state, per mode; fake_device() resets a mode's entry, so
# every suite run starts with a device that has sent nothing yet.
REPLAY: dict[str, dict] = {}
FIXED_HELLO = Path(tempfile.gettempdir()) / "tls-spike-sim-fixed-client-hello.bin"
PUTS: dict[str, int] = {}
PUT_LOCK = threading.Lock()
# The suite's PUT timeout in the sim, so a fake that never answers costs
# seconds rather than the real 90.
SLOW_PUT_TIMEOUT = 6.0


def payload_for(seed: int, n: int) -> bytes:
    """M2-SPEC.md section 7, written out again rather than imported from the suite."""
    return bytes(((((seed + i) & 0xFFFFFFFF) * 2654435761) & 0xFFFFFFFF) >> 24
                 for i in range(n))


def run_spike(mode: str, query: dict) -> dict:
    host, port = query["host"], int(query["port"])
    sni, verify, n = query["sni"], query["verify"] == "1", int(query["echo"])
    seed = int(query["seed"])
    cafile = pki.pki_dir() / "test-ca.pem"
    if mode == "no-test-ca":
        cafile = pki.pki_dir() / "untrusted-root" / "root.pem"
    effective_verify = verify and mode != "verify-ignored"
    stats = {"heap_free": 180000, "heap_min_ever": 120000, "largest_block": 90000,
             "stack_free": 2600, "sessions_open": 0}
    no_time = mode.startswith("no-time")
    # Amendment 9 A: the time fields come from the STATS right after OPEN, so a
    # failed handshake still carries them; "none" only when OPEN failed.
    result = {"ok": False, "stage": "connect", "error": "", "steps": 0,
              "time_source": "none" if no_time else "nios",
              "esp_time": 0 if no_time else int(time.time()),
              "handshake_ms": 0, "handshake_us": 0, "tls_version": 0, "ciphersuite": 0,
              "group": 0, "echo_sent": 0, "echo_received": 0, "echo_ok": False,
              "step_max_ms": 0, "open_ms": 0,
              "sessions_open_after": 1 if mode in ("session-leak", "orphan-before") else 0,
              "stats_before": dict(stats), "stats_after": dict(stats),
              "stats_peak": dict(stats, heap_free=180000 - 46 * 1024)}
    if mode == "orphan-before":
        result["stats_before"]["sessions_open"] = 1
    replay = REPLAY.setdefault(mode, {})
    if mode == "replay-hello" and replay.get("hello"):
        # Every connection after the first sends the first one's ClientHello
        # again, byte for byte: a client whose RNG repeats, made visible.
        with socket.create_connection((host, port), timeout=READ_TIMEOUT) as raw:
            raw.sendall(replay["hello"])
            try:
                raw.recv(65536)
            except OSError:
                pass
        result.update(stage="handshake", error="replayed ClientHello", open_ms=2,
                      stats_peak=dict.fromkeys(stats, 0))
        return result
    if mode == "witness-cross-run" and not replay.get("used"):
        replay["used"] = True
        with socket.create_connection((host, port), timeout=READ_TIMEOUT) as raw:
            raw.sendall(FIXED_HELLO.read_bytes())
            try:
                raw.recv(65536)
            except OSError:
                pass
        result.update(stage="handshake", error="fixed ClientHello", open_ms=2,
                      stats_peak=dict.fromkeys(stats, 0))
        return result
    if mode == "no-time-correct" and verify:
        # The Nios opened the socket before OPEN refused; nothing is sent.
        socket.create_connection((host, port), timeout=READ_TIMEOUT).close()
        result.update(stage="open", error="TLS open refused: no trusted time for verification",
                      stats_peak=dict.fromkeys(stats, 0))
        return result
    started = time.monotonic()
    session = FakeSession(mode, host, port, sni, effective_verify, cafile)
    reason = session.handshake()
    if mode == "replay-hello" and not replay.get("hello"):
        replay["hello"] = session.first_flight
    handshake_s = time.monotonic() - started
    result["steps"] = session.steps
    payload = payload_for(seed, n)
    if mode == "wrong-payload":
        payload = (bytes(range(256)) * (n // 256 + 1))[:n]
    if reason:
        session.close()
        error = ("X509 - Certificate verification failed (-0x2700)"
                 if reason.startswith("verify") else f"SSL - {reason}")
        # What the route sends on a FAILED handshake (m2-adversarial.md §1): no
        # ESP32 figure and a zeroed stats_peak, which is only taken once the
        # session is established.
        result.update(stage="handshake", error=error, handshake_ms=round(handshake_s * 1000),
                      handshake_us=0, step_max_ms=STEP_DELAY_MS,
                      stats_peak=dict.fromkeys(stats, 0))
        if mode == "pre-a-shape":
            result.update(time_source="none", esp_time=0)
        if mode in ("fallback-retry", "fallback-reports-failed") and reason.startswith("verify"):
            retry = FakeSession(mode, host, port, sni, False, cafile)
            if retry.handshake() is None:
                retry.echo(payload)
            retry.close()
            if mode == "fallback-retry":
                fill_success(result, retry, n, True, handshake_s)
        return result
    got = session.echo(payload)
    if mode == "echo-corrupt-once" and got and not replay.get("corrupted"):
        replay["corrupted"] = True
        got = bytes([got[0] ^ 0x40]) + got[1:]
    if mode in ("echo-corrupt-honest", "echo-corrupt-liar") and got:
        got = bytes([got[0] ^ 0x40]) + got[1:]
    echo_ok = got == payload
    if mode in ("echo-corrupt-liar", "echo-always-ok"):
        echo_ok = True
    session.close()
    fill_success(result, session, n, echo_ok, handshake_s, len(got))
    return result


def fill_success(result: dict, session: FakeSession, n: int, echo_ok: bool,
                 handshake_s: float, received: int | None = None) -> None:
    final = session.negotiated()
    group = 0x001D if session.mode == "lie-group" else 0
    result.update({
        "ok": echo_ok, "stage": "done" if echo_ok else "echo",
        "error": "" if echo_ok else "echo mismatch",
        "tls_version": final.get("version"),
        "ciphersuite": final.get("cipher_suite"),
        "group": group,
        "handshake_ms": max(1, round(handshake_s * 1000)),
        "handshake_us": max(1, int(handshake_s * 1e6 * 0.8)),
        "echo_sent": n,
        "echo_received": n if received is None else received,
        "echo_ok": echo_ok,
        "steps": session.steps,
        "step_max_ms": STEP_DELAY_MS,
        "open_ms": 2,
    })
    if session.mode == "fast-clock":
        result["handshake_ms"] = result["handshake_us"] = 1
    if session.mode == "nios-below-esp":
        result["handshake_us"] = result["handshake_ms"] * 1000 + 20000


def make_fixed_hello() -> None:
    """One real ClientHello, kept in a file so two runs can send the same bytes."""
    if FIXED_HELLO.exists():
        return
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = client_context(True, pki.pki_dir() / "test-ca.pem").wrap_bio(
        incoming, outgoing, server_hostname=pki.SNI)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    FIXED_HELLO.write_bytes(outgoing.read())


def fake_device(mode: str) -> ThreadingHTTPServer:
    REPLAY[mode] = {}
    PUTS[mode] = 0
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_PUT(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            with PUT_LOCK:
                PUTS[mode] = PUTS.get(mode, 0) + 1
                first = PUTS[mode] == 1
            if mode == "slow-first-put" and first:
                # Say nothing until the suite has given up, then drop the request.
                time.sleep(SLOW_PUT_TIMEOUT * 2)
                return
            query = dict(urllib.parse.parse_qsl(parsed.query))
            if mode in ("stock", "stale-image") or parsed.path != ROUTE:
                self.wfile.write(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                return
            try:
                body = json.dumps(run_spike(mode, query)).encode()
                code = 200
            except Exception as exc:  # noqa: BLE001
                body = json.dumps({"ok": False, "stage": "fake", "error": str(exc)}).encode()
                code = 500
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


LINE = re.compile(r"^\[\d+\] (?P<label>.*?) \.\.\. (?P<verdict>OK|FAIL|WARN|SKIP)\b(?P<rest>.*)$")


def scenario_key(label: str) -> str | None:
    table = [("f: PUT", "f"), ("a: ", "a"), ("b: ", "b"), ("c: the server allows X25519", "c-x25519"),
             ("c: the server allows P-256", "c-p256"), ("control: the server flips", "echo-flip"),
             ("control: the server withholds", "echo-short"), ("d: hostname", "d-mismatch"),
             ("d: an untrusted", "d-untrusted"), ("d: an expired", "d-expired"),
             ("e: SPIKE-ONLY", "e-verify-off")]
    return next((key for prefix, key in table if label.startswith(prefix)), None)


def run_mode(mode: str, repeat: int, work: Path) -> dict:
    """One suite run against the mode's fake, or two for the cross-run witness."""
    witness = work / f"{mode}-witness.jsonl"
    witness.unlink(missing_ok=True)
    if mode == "witness-cross-run":
        run_once(mode, repeat, work, witness, "-first")
    return run_once(mode, repeat, work, witness, "")


def run_once(mode: str, repeat: int, work: Path, witness: Path, suffix: str) -> dict:
    results = work / f"{mode}{suffix}-results.json"
    # The suite never overwrites a results file; these are the sim's own.
    results.unlink(missing_ok=True)
    device = fake_device(mode)
    # The host running the sim is rarely quiet, so the load is faked: 9 for the
    # high-load fake, 0.5 for every other, which lets P2 be judged.
    env = dict(os.environ, U64_REST_PORT=str(device.server_address[1]),
               TLS_SPIKE_FAKE_LOADAVG="9" if mode == "high-load" else "0.5")
    command = [sys.executable, str(HERE / "tls_spike_test.py"), "-H", "127.0.0.1",
               "--server-ip", "127.0.0.1", "--repeat", str(repeat), "--color", "never",
               "--results", str(results), "--witness-log", str(witness),
               "--log-dir", str(work / f"{mode}{suffix}")]
    if mode == "stale-image":
        command.append("--expect-spike")
    if mode == "slow-first-put":
        command += ["--spike-timeout", str(SLOW_PUT_TIMEOUT)]
    if mode == "expect-prior-empty":
        command.append("--expect-prior-hellos")
    started = time.monotonic()
    completed = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    device.shutdown()
    verdicts: dict[str, list[str]] = {}
    lines = completed.stdout.splitlines()
    for line in lines:
        match = LINE.match(line)
        if match:
            key = scenario_key(match["label"])
            if key:
                verdicts.setdefault(key, []).append(match["verdict"] + match["rest"])
    return {"mode": mode, "exit": completed.returncode, "verdicts": verdicts,
            "puts": PUTS.get(mode, 0),
            # One PUT per scenario line, and the route check's line stands in for
            # the scenario only when the route was absent (then it is alone).
            "calls": (sum(1 for line in lines if LINE.match(line)
                          and scenario_key(LINE.match(line)["label"]) not in (None, "f"))
                      or len(verdicts.get("f", []))),
            "seconds": round(time.monotonic() - started, 1),
            "suite_line": next((l for l in lines if l.startswith("tls_spike_test:")), ""),
            "fixture_fails": [l for l in lines if "fixtures" in l and "FAIL" in l],
            "stdout": completed.stdout, "stderr": completed.stderr}


def expected_ok(mode: str, result: dict) -> tuple[bool, str]:
    _, must_fail = MODES[mode]
    failed = {k for k, v in result["verdicts"].items() if any(x.startswith("FAIL") for x in v)}
    if result["fixture_fails"]:
        return False, f"fixture failures: {result['fixture_fails']}"
    if result["puts"] > result["calls"]:
        return False, (f"{result['puts']} PUTs reached the device for {result['calls']} "
                       "scenarios: a PUT was re-issued")
    said = MUST_SAY.get(mode, "") in result["stdout"]
    unsaid = "" if said else f", never said {MUST_SAY[mode]!r}"
    if must_fail is None:
        return (result["exit"] == 0 and not failed and said,
                f"exit {result['exit']}, failed {sorted(failed)}{unsaid}")
    ok = result["exit"] != 0 if must_fail or mode in EXIT_1 else result["exit"] == 0
    warned = {k for k, v in result["verdicts"].items() if any(x.startswith("WARN") for x in v)}
    missing = MUST_WARN.get(mode, set()) - warned
    return (ok and failed == must_fail and not missing and said,
            f"exit {result['exit']}, failed {sorted(failed)}, expected {sorted(must_fail)}"
            + (f", no WARN on {sorted(missing)}" if missing else "") + unsaid)


# ------------------------------------------------------------ golden replies --
#
# Amendments 9 E and 10 (M2-SPEC.md sections 17 and 19): the Nios lane's host
# harness records the route's REAL answer for every exit path, wrapped as
#   {stem, exit_path, request{host, port, sni, verify, ca, echo, seed},
#    http_status, response}
# with response null for an empty body. Each file is classified by the suite's
# own classify_reply and judged by its own judge_outcome, beside a real server
# record for its chain, made by this host's TLS client against the suite's echo
# server with the request's seed and echo count. Only fields that depend on the
# live server are patched, and every patch is printed.
#
# stem -> (scenario kind, chain, verify, what the server sees, expected verdict)
#   server: "tls" (a clean echo), "flip" (the server flips the last echoed
#   byte), "reject" (the host client, verifying, refuses the chain), or "none"
#   (no connection)
#   verify: 0, 1, or None for a path that holds either way (the request's own
#   value is then used)
#   verdict: "pass" (no problems), "precondition" (a correct refusal the rig
#   cannot run past), "bad-request" (the suite classified an HTTP 400), or
#   "fail" (a FAIL that is none of those and never "fail-closed rule broken")
#
# The three must-fail replies may carry the same error (-0x2700, the one code
# mbedTLS returns for every verification failure); their judge tells them apart
# by the server-side alert, never by the device's error text.
GOLDEN_EXPECT = {
    # the twelve of amendment 10
    "success_ecdsa": ("established", "ecdsa", 1, "tls", "pass"),
    "success_rsa": ("established", "rsa", 1, "tls", "pass"),
    "verify_off": ("established", "mismatch", 0, "tls", "pass"),
    "mismatch": ("failed", "mismatch", 1, "reject", "pass"),
    "untrusted": ("failed", "untrusted", 1, "reject", "pass"),
    "expired": ("failed", "expired", 1, "reject", "pass"),
    "no_time": ("established", "ecdsa", 1, "none", "precondition"),
    "bad_param": ("established", "ecdsa", None, "none", "bad-request"),
    "connect_fail": ("established", "ecdsa", 1, "none", "fail"),
    "open_timeout": ("established", "ecdsa", 1, "none", "fail"),
    "handshake_timeout": ("established", "ecdsa", 1, "none", "fail"),
    "echo_mismatch": ("echo-broken", "ecdsa", 1, "flip", "pass"),
    # the supervisor's three extra stems (amendment 10 follow-up; the name
    # verify_without_sni is final)
    "no_entropy": ("established", "ecdsa", None, "none", "precondition"),
    "step_timeout": ("established", "ecdsa", 1, "none", "fail"),
    "verify_without_sni": ("established", "ecdsa", None, "none", "bad-request"),
    # one per further Nios exit-path row (m2-nios.md section 5)
    "bad_param_host": ("established", "ecdsa", None, "none", "bad-request"),
    "memory_fail": ("established", "ecdsa", 1, "none", "fail"),
    "socket_fail": ("established", "ecdsa", 1, "none", "fail"),
    "connect_timeout": ("established", "ecdsa", 1, "none", "fail"),
    "socket_options_fail": ("established", "ecdsa", 1, "none", "fail"),
    "open_invalid": ("established", "ecdsa", 1, "none", "fail"),
    "handshake_send_fail": ("established", "ecdsa", 1, "none", "fail"),
    "handshake_closed": ("established", "ecdsa", 1, "none", "fail"),
    "handshake_eof": ("established", "ecdsa", 1, "none", "fail"),
    "handshake_deadline": ("established", "ecdsa", 1, "none", "fail"),
    "echo_recv_fail": ("established", "ecdsa", 1, "none", "fail"),
    "echo_send_fail": ("established", "ecdsa", 1, "none", "fail"),
    "echo_silent": ("established", "ecdsa", 1, "none", "fail"),
    "echo_step_fail": ("established", "ecdsa", 1, "none", "fail"),
    "echo_closed": ("established", "ecdsa", 1, "none", "fail"),
    # exit 16: the run completed, CLOSE failed, and the session is left open;
    # sessions_open_after=1 must FAIL it (amendment 9 D)
    "close_fail": ("established", "ecdsa", 1, "tls", "fail"),
}
GOLDEN_ENV = "TLS_SPIKE_GOLDEN"
# The fields of a golden reply that depend on the server it met, not on the
# route's code, and so are taken from the live record instead. esp_time is the
# clock at recording time; it is moved to now only when it was nonzero.
LIVE_FIELDS = ("tls_version", "ciphersuite")
# What a stem's reply itself must show, beyond its verdict: (stage, error pattern).
# Amendment 11 E: what every stem's reply itself must show, whatever the
# judges then decide: (ok, stage, error pattern). A golden that claimed success
# on a failure path would otherwise pass on the missing server record alone.
# The bad-request stems carry no route JSON and must be HTTP 400 instead.
TIMEOUT = r"time\s*-?\s*out|timed\s+out|no answer in time"
GOLDEN_REPLY = {
    "success_ecdsa": (True, "done", r"^$"),
    "success_rsa": (True, "done", r"^$"),
    "verify_off": (True, "done", r"^$"),
    "mismatch": (False, "handshake", r"-9984|2700|verif"),
    "untrusted": (False, "handshake", r"-9984|2700|verif"),
    "expired": (False, "handshake", r"-9984|2700|verif"),
    "no_time": (False, "open", r"trust\w*\s+time|clock"),
    "no_entropy": (False, "open", r"entropy"),
    "connect_fail": (False, "connect", r"connect"),
    "connect_timeout": (False, "connect", TIMEOUT),
    "memory_fail": (False, "connect", r"memory"),
    "socket_fail": (False, "connect", r"socket"),
    "socket_options_fail": (False, "connect", r"socket_options"),
    "open_invalid": (False, "open", r"malformed|invalid"),
    "open_timeout": (False, "open", TIMEOUT),
    "step_timeout": (False, "handshake", TIMEOUT),
    "handshake_send_fail": (False, "handshake", r"send"),
    "handshake_closed": (False, "handshake", r"CLOSED"),
    "handshake_eof": (False, "handshake", r"pipe|closed|eof|reset"),
    "handshake_deadline": (False, "handshake", TIMEOUT),
    "handshake_timeout": (False, "handshake", TIMEOUT),
    "echo_recv_fail": (False, "echo", r"recv"),
    "echo_send_fail": (False, "echo", r"send"),
    "echo_silent": (False, "echo", TIMEOUT),
    "echo_step_fail": (False, "echo", TIMEOUT),
    "echo_closed": (False, "echo", r"CLOSED"),
    "echo_mismatch": (False, "echo", r"differ|mismatch|compare"),
    "close_fail": (False, "close", TIMEOUT),
}
_BAD_REQUEST = {stem for stem, entry in GOLDEN_EXPECT.items() if entry[4] == "bad-request"}
assert set(GOLDEN_REPLY) | _BAD_REQUEST == set(GOLDEN_EXPECT), "every stem needs a reply check"


def golden_case(stem: str, wrapped: dict, work: Path) -> tuple[bool, str, list[str]]:
    import tls_spike_test as suite
    kind, chain, verify, seen, want = GOLDEN_EXPECT[stem]
    request = wrapped.get("request") or {}
    notes: list[str] = []
    if wrapped.get("stem") != stem:
        return False, f"file {stem}.json says stem {wrapped.get('stem')!r}", notes
    if verify is None:
        # A bad-request row may carry an invalid or missing verify; it never
        # reaches the judges that use it.
        given = request.get("verify")
        verify = given if isinstance(given, int) and given in (0, 1) else 1
    elif int(request.get("verify", -1)) != verify:
        return False, (f"request verify={request.get('verify')!r}, but {stem} is a verify="
                       f"{verify} path"), notes
    if stem in _BAD_REQUEST:
        if wrapped.get("http_status") != 400:
            return False, (f"{stem} is a bad-request path but answered HTTP "
                           f"{wrapped.get('http_status')!r}"), notes
    else:
        want_ok, stage, pattern = GOLDEN_REPLY[stem]
        response = wrapped.get("response")
        response = response if isinstance(response, dict) else {}
        error = str(response.get("error", ""))
        if (response.get("ok") is not want_ok or response.get("stage") != stage
                or not re.search(pattern, error, re.IGNORECASE)):
            return False, (f"the reply shows ok={response.get('ok')!r}, stage "
                           f"{response.get('stage')!r}, error {error!r}; {stem} must show "
                           f"ok={want_ok}, stage {stage!r} and an error matching "
                           f"{pattern!r}"), notes
    n = int(request.get("echo") or 0) or suite.DEFAULT_ECHO_BYTES
    seed = int(request.get("seed") or 0)
    manifest = pki.generate(pki.pki_dir())
    records: list[dict] = []
    if seen != "none":
        mangle = "flip-last" if seen == "flip" else "none"
        server = suite.Server(suite.ServerConfig(chain, mangle=mangle), pki.pki_dir(),
                              work / f"golden-{stem}.jsonl", n)
        server.start()
        try:
            suite.host_control(server, pki.SNI, bool(verify), None,
                               suite.expected_payload(seed, n))
            records = server.new_records(suite.RECORD_WAIT, stray=0.2)
        finally:
            server.stop()
    response = wrapped.get("response")
    if response is None:
        body = b""
    elif isinstance(response, str):
        body = response.encode()
    else:
        body = json.dumps(response).encode()

    class Args:
        sni = pki.SNI
        echo_bytes = n

    scenario = suite.Scenario(stem, stem, suite.ServerConfig(chain), verify=verify, expect=kind)
    try:
        device = suite.classify_reply(suite.ROUTE, int(wrapped.get("http_status", 0)), body,
                                      request)
    except suite.Failure as exc:
        problems, warning = [str(exc)], None
    else:
        device = dict(device)
        if records and records[0]["handshake_ok"]:
            live = {"tls_version": records[0]["negotiated"]["version"],
                    "ciphersuite": records[0]["negotiated"]["cipher_suite"]}
            for name in LIVE_FIELDS:
                if device.get(name) not in (0, None) and device.get(name) != live[name]:
                    notes.append(f"patched {name}: {device.get(name)!r} -> {live[name]!r}")
                    device[name] = live[name]
        if isinstance(device.get("esp_time"), int) and device["esp_time"]:
            now = int(time.time())
            notes.append(f"patched esp_time: {device['esp_time']} -> {now}")
            device["esp_time"] = now
        outcome = suite.Outcome(scenario, seed, int(wrapped["http_status"]), device, records)
        problems, warning = suite.judge_outcome(Args, outcome, manifest, positives_ok=True)
        # Whatever decides the verdict, the reply itself has to meet the
        # section 7/9/17 contract on every exit path; that is the seam the
        # adversarial review found untested (m2-adversarial.md §1).
        contract = suite.contract_problems(device)
        if contract:
            return False, f"[{wrapped.get('exit_path')}] the reply breaks the contract: " \
                          f"{contract}", notes
    first = problems[0] if problems else ""
    if want == "pass":
        ok = not problems
    elif want == "precondition":
        ok = first.startswith("precondition")
    elif want == "bad-request":
        ok = "answered HTTP 400" in first
    else:
        # A plain FAIL: never a correct refusal, never a security break, never
        # the "none past OPEN" contract FAIL, which is about OPEN having run.
        ok = (bool(problems) and not first.startswith("precondition")
              and not any(word in first for word in ("fail-closed rule", "past OPEN")))
        if stem == "close_fail":
            ok = ok and any("sessions_open_after=1" in problem for problem in problems)
    said = first or warning or "no problems"
    return ok, f"[{wrapped.get('exit_path')}] expected {want}: {said[:160]}", notes


def run_golden(directory: Path, work: Path) -> bool:
    found = {path.stem: path for path in sorted(directory.glob("*.json"))}
    if not found:
        print(f"GOLDEN NOT RUN  no files in {directory} (amendment 10 is not yet exercised)")
        return False
    all_ok = True
    for stem in sorted(set(found) | set(GOLDEN_EXPECT)):
        if stem not in GOLDEN_EXPECT:
            print(f"UNEXPECTED   golden {stem:18} a file with no expected verdict in GOLDEN_EXPECT")
            all_ok = False
            continue
        if stem not in found:
            print(f"UNEXPECTED   golden {stem:18} a required stem with no file")
            all_ok = False
            continue
        try:
            ok, why, notes = golden_case(stem, json.loads(found[stem].read_text()), work)
        except Exception as exc:  # noqa: BLE001
            ok, why, notes = False, f"could not judge it: {exc!r}", []
        all_ok &= ok
        print(f"{'AS EXPECTED' if ok else 'UNEXPECTED '}  golden {stem:18} {why}")
        for note in notes:
            print(f"      {note}")
    return all_ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", action="append", choices=tuple(MODES))
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--keep", help="write every run's output under this directory")
    parser.add_argument("--golden-dir",
                        default=os.environ.get(GOLDEN_ENV) or str(HERE / "golden"),
                        help=f"the Nios lane's golden route replies (amendment 10; default "
                             f"${GOLDEN_ENV}, else golden/ beside this file)")
    parser.add_argument("--no-golden", action="store_true",
                        help="skip the golden contract test, and say so")
    parser.add_argument("--golden-only", action="store_true")
    args = parser.parse_args()
    pki.generate(pki.pki_dir())
    make_fixed_hello()
    work = Path(args.keep or tempfile.mkdtemp(prefix="tls-spike-sim-"))
    work.mkdir(parents=True, exist_ok=True)
    golden_ok = True
    if args.no_golden:
        print("GOLDEN SKIPPED  --no-golden")
    else:
        golden_ok = run_golden(Path(args.golden_dir), work)
    if args.golden_only:
        return 0 if golden_ok else 1
    modes = args.mode or list(MODES)
    with ThreadPoolExecutor(args.jobs) as pool:
        results = list(pool.map(lambda m: run_mode(m, args.repeat, work), modes))
    all_ok = True
    for result in results:
        mode = result["mode"]
        ok, why = expected_ok(mode, result)
        all_ok &= ok
        (work / f"{mode}.out").write_text(result["stdout"] + result["stderr"])
        print(f"{'AS EXPECTED' if ok else 'UNEXPECTED '}  {mode:24} {why}  ({result['seconds']}s)")
        for key, verdicts in sorted(result["verdicts"].items()):
            shown = sorted({v.split(' (')[0][:4] for v in verdicts})
            first_fail = next((v for v in verdicts if v.startswith("FAIL")), "")
            print(f"      {key:14} {'/'.join(shown):10} {first_fail[:150]}")
        print(f"      {result['suite_line'][:200]}")
    print(f"outputs in {work}")
    return 0 if all_ok and golden_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
