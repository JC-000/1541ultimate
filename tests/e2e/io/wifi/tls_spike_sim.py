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
    "no-alert": ("drops the ESP32's final ciphertext, so the server never sees the alert",
                 set()),
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
    "nios-below-esp": ("reports an ESP32 handshake_us 10 ms longer than the Nios wall clock",
                       {"a", "b", "c-x25519", "c-p256", "e-verify-off"}),
    "high-load": ("a correct device, on a host whose load average is 9 (faked): P2 must be "
                  "held back as INCONCLUSIVE", None),
    "fast-clock": ("reports handshake_ms of 1 while the server watched tens of ms; this is "
                   "a WARN by design, because a busy host inflates the server's window",
                   set()),
}


# Modes whose deviation the suite can only flag, and the scenarios that must
# carry the WARN.
# Modes whose failures must carry this text, where the set of failed scenarios
# alone cannot tell two fakes apart.
MUST_SAY = {
    "slow-first-put": "no answer to PUT /v1/machine:tlsspike within",
    "stock": "this firmware has no TLS spike route",
    "stale-image": "a stale or wrong image",
    "correct": "P2a OUTSIDE",
    "high-load": "P2a INCONCLUSIVE (host load)",
    "nios-below-esp": "the Nios clock (handshake_ms=",
    "no-time-correct": "precondition: the device has no trusted time",
    "no-time-verifies": "fail-closed rule broken",
    "wrong-payload": "not the payload for seed",
}

MUST_WARN = {
    "no-alert": {"d-mismatch", "d-untrusted", "d-expired"},
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

    def flush(self) -> None:
        data = self.outgoing.read()
        if data:
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
             "state": 0, "sessions_open": 0, "stack_free": 2600}
    no_time = mode.startswith("no-time")
    result = {"ok": False, "stage": "connect", "error": "", "steps": 0,
              "time_source": "none" if no_time else "nios",
              "esp_time": 0 if no_time else int(time.time()),
              "handshake_ms": 0, "handshake_us": 0, "tls_version": 0, "ciphersuite": 0,
              "group": 0, "echo_sent": 0, "echo_received": 0, "echo_ok": False,
              "stats_before": dict(stats), "stats_after": dict(stats),
              "stats_peak": dict(stats, heap_free=180000 - 46 * 1024)}
    if mode == "no-time-correct" and verify:
        # The Nios opened the socket before OPEN refused; nothing is sent.
        socket.create_connection((host, port), timeout=READ_TIMEOUT).close()
        result.update(stage="open", error="TLS open refused: no trusted time for verification")
        return result
    started = time.monotonic()
    session = FakeSession(mode, host, port, sni, effective_verify, cafile)
    reason = session.handshake()
    handshake_s = time.monotonic() - started
    result["steps"] = session.steps
    payload = payload_for(seed, n)
    if mode == "wrong-payload":
        payload = (bytes(range(256)) * (n // 256 + 1))[:n]
    if reason:
        session.close()
        error = ("X509 - Certificate verification failed (-0x2700)"
                 if reason.startswith("verify") else f"SSL - {reason}")
        result.update(stage="handshake", error=error,
                      handshake_ms=round(handshake_s * 1000))
        if mode in ("fallback-retry", "fallback-reports-failed") and reason.startswith("verify"):
            retry = FakeSession(mode, host, port, sni, False, cafile)
            if retry.handshake() is None:
                retry.echo(payload)
            retry.close()
            if mode == "fallback-retry":
                fill_success(result, retry, n, True, handshake_s)
        return result
    got = session.echo(payload)
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
    })
    if session.mode == "fast-clock":
        result["handshake_ms"] = result["handshake_us"] = 1
    if session.mode == "nios-below-esp":
        result["handshake_us"] = result["handshake_ms"] * 1000 + 10000


def fake_device(mode: str) -> ThreadingHTTPServer:
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
    device = fake_device(mode)
    # The host running the sim is rarely quiet, so the load is faked: 9 for the
    # high-load fake, 0.5 for every other, which lets P2 be judged.
    env = dict(os.environ, U64_REST_PORT=str(device.server_address[1]),
               TLS_SPIKE_FAKE_LOADAVG="9" if mode == "high-load" else "0.5")
    command = [sys.executable, str(HERE / "tls_spike_test.py"), "-H", "127.0.0.1",
               "--server-ip", "127.0.0.1", "--repeat", str(repeat), "--color", "never",
               "--results", str(work / f"{mode}-results.json"),
               "--log-dir", str(work / mode)]
    if mode == "stale-image":
        command.append("--expect-spike")
    if mode == "slow-first-put":
        command += ["--spike-timeout", str(SLOW_PUT_TIMEOUT)]
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
    ok = result["exit"] != 0 if must_fail else result["exit"] == 0
    warned = {k for k, v in result["verdicts"].items() if any(x.startswith("WARN") for x in v)}
    missing = MUST_WARN.get(mode, set()) - warned
    return (ok and failed == must_fail and not missing and said,
            f"exit {result['exit']}, failed {sorted(failed)}, expected {sorted(must_fail)}"
            + (f", no WARN on {sorted(missing)}" if missing else "") + unsaid)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", action="append", choices=tuple(MODES))
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--keep", help="write every run's output under this directory")
    args = parser.parse_args()
    pki.generate(pki.pki_dir())
    work = Path(args.keep or tempfile.mkdtemp(prefix="tls-spike-sim-"))
    work.mkdir(parents=True, exist_ok=True)
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
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
