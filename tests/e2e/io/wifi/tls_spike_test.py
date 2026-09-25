#!/usr/bin/env python3
"""E2E: the ESP32 TLS 1.3 spike (M2), judged from the server's side of the wire.

SPIKE CODE, not for upstream, like the firmware route it drives.

The device runs a TLS 1.3 client on its ESP32, pumped over the serial link by a
spike route on the Nios (M2 spec section 3). This suite starts a TLS 1.3-only
echo server on this machine (tls_spike_server.py), asks the device to connect to
it, and holds everything the device reports against what the server logged for
that one connection: the version, cipher suite and group from the ServerHello
the server sent, the SNI from the ClientHello it received, the plaintext bytes
it received and echoed, and the alert the client sent when it gave up. The
device's own claim is never the evidence for itself.

Scenarios (spec section 4):
  a   ecdsa chain, verify on, test CA: ESTABLISHED, TLS 1.3, echo intact
  b   rsa chain, the same
  c   the server allows X25519 only, then P-256 only: the device reports, and
      the server shows, exactly the allowed group
  d   must fail at the handshake with no plaintext: hostname mismatch,
      untrusted CA, expired certificate
  e   verify off against the mismatched host completes: a SPIKE-ONLY mode
  f   the route itself: stock firmware answers 404 with an empty body
Controls, because the server cannot see what the device received back:
  echo-flip  the server flips the last echoed byte; the device must say the
             echo was NOT intact
  echo-short the server withholds the last byte; the device must say the echo
             was NOT intact, and close its socket anyway

Registered predictions (spec section 5) are judged by tls_spike_predictions.py,
whose hash is checked against the committed registry before and after the run.
"""

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# The one stanza that puts the shared library on sys.path; see tests/lib/bootstrap.py.
sys.path.insert(0, str(next(p for p in Path(__file__).resolve().parents
                            if (p / "tests" / "lib").is_dir()) / "tests" / "lib"))
import bootstrap  # noqa: E402,F401
import cli  # noqa: E402

import targets
from report import (Failure, check, check_count, check_fail, check_ok, check_start,
                    check_warn, detail, format_exception, suite_fail, suite_ok)
from rest import RestClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, bootstrap.directory("e2e", "io", "wifi"))
import tls_spike_pki as pki  # noqa: E402
import tls_spike_predictions as predictions  # noqa: E402

SUITE = "tls_spike_test"

# The route of spec section 3. The spec gives it as an example, so it is one
# constant, and --route overrides it without an edit.
ROUTE = "/v1/machine:tlsspike"

# The device's JSON, field by field. The spec names the facts but not the keys;
# these are the keys this suite reads, and the one place to change if the Nios
# lane chose others. A dotted key reads into a nested object.
FIELDS = {
    "ok": "ok",
    "stage": "stage",
    "error": "error",
    "state": "state",
    "handshake_ms": "handshake_ms",
    "handshake_us": "handshake_us",
    "tls_version": "tls_version",
    "ciphersuite": "ciphersuite",
    "group": "group",
    "echo_sent": "echo_sent",
    "echo_received": "echo_received",
    "echo_ok": "echo_ok",
    "steps": "steps",
    "heap_free_before": "stats_before.heap_free",
    "heap_free_after": "stats_after.heap_free",
    "heap_free_peak": "stats_peak.heap_free",
}
STATS_KEYS = ("heap_free", "heap_min_ever", "largest_block")

# mbedTLS returns this from the handshake for every certificate verification
# failure: the X.509 verify sets flags, and any flag makes it fail with
# MBEDTLS_ERR_X509_CERT_VERIFY_FAILED (-0x2700). Which flag it was travels in the
# alert, not in the code.
X509_CERT_VERIFY_FAILED = -0x2700
STATE_FAILED = 3

TLS13 = 0x0304
CIPHER_SUITES = {"TLS_AES_128_GCM_SHA256": 0x1301, "TLS_AES_256_GCM_SHA384": 0x1302,
                 "TLS_CHACHA20_POLY1305_SHA256": 0x1303}
GROUP_SPELLINGS = {"X25519": 0x001D, "SECP256R1": 0x0017, "P256": 0x0017,
                   "PRIME256V1": 0x0017, "P_256": 0x0017}
VERSION_SPELLINGS = {"TLSV1.3", "TLS1.3", "TLS 1.3", "1.3", "TLSV13", "TLS1_3"}

DEFAULT_ECHO_BYTES = 3000   # more than one 1024-byte step each way (spec section 2)
DEFAULT_REPEAT = 5
SPIKE_TIMEOUT = 60.0        # one REST call: connect, handshake, echo and close
RECORD_WAIT = 10.0          # after the reply, for the server's connection record
STRAY_WAIT = 2.0            # after that, for a second connection nobody asked for
SERVER_IDLE_TIMEOUT = 90.0  # longer than one REST call, so an open socket shows


MANGLED = {"flip-last": "flipped", "drop-last": "withheld"}


class RouteAbsent(Failure):
    """The firmware has no spike route: the stock RED."""


def normalise_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def normalise_version(value) -> int:
    number = normalise_int(value)
    if number is not None:
        return number
    if isinstance(value, str) and value.strip().upper() in VERSION_SPELLINGS:
        return TLS13
    raise Failure(f"device reported tls_version {value!r}, which the oracle cannot map; "
                  "add the spelling to VERSION_SPELLINGS only if it names a real version")


def normalise_cipher(value) -> int:
    number = normalise_int(value)
    if number is not None:
        return number
    if isinstance(value, str):
        text = value.strip().upper().replace("-", "_")
        text = text.replace("TLS1_3_", "TLS_")
        if text in CIPHER_SUITES:
            return CIPHER_SUITES[text]
    raise Failure(f"device reported ciphersuite {value!r}, which the oracle cannot map")


def normalise_group(value) -> int:
    number = normalise_int(value)
    if number is not None:
        return number
    if isinstance(value, str):
        text = value.strip().upper().replace("-", "")
        if text in GROUP_SPELLINGS:
            return GROUP_SPELLINGS[text]
    raise Failure(f"device reported group {value!r}, which the oracle cannot map")


def field_of(report_: dict, name: str, required: bool = True):
    node = report_
    for part in FIELDS[name].split("."):
        if not isinstance(node, dict) or part not in node:
            if required:
                raise Failure(f"device JSON has no {FIELDS[name]!r} ({name}); "
                              f"keys: {sorted(report_)}")
            return None
        node = node[part]
    return node


# ------------------------------------------------------------------ the server --

@dataclass
class ServerConfig:
    chain: str
    groups: str = "both"
    mangle: str = "none"


@dataclass
class Server:
    """One tls_spike_server.py process and the log it writes."""

    config: ServerConfig
    pki_dir: Path
    log: Path
    expect_bytes: int
    process: subprocess.Popen | None = None
    port: int = 0
    seen: int = 0

    def start(self) -> None:
        self.log.write_text("")
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "tls_spike_server.py"), "--pki-dir", str(self.pki_dir),
             "--chain", self.config.chain, "--groups", self.config.groups,
             "--mangle", self.config.mangle, "--expect-bytes", str(self.expect_bytes),
             "--idle-timeout", str(SERVER_IDLE_TIMEOUT), "--log", str(self.log)],
            stdout=subprocess.PIPE, text=True)
        line = self.process.stdout.readline() if self.process.stdout else ""
        if not line.startswith("LISTENING "):
            self.stop()
            raise Failure(f"the echo server did not start: {line!r}")
        self.port = int(line.split()[1])

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def records(self) -> list[dict]:
        lines = [line for line in self.log.read_text().splitlines() if line.strip()]
        return [json.loads(line) for line in lines]

    def new_records(self, wait: float, stray: float = STRAY_WAIT) -> list[dict]:
        """The connections that ended since the last call, waiting for the first.

        Then it waits `stray` longer, so a second connection the device opened
        on its own (a retry, a fallback) is counted with the first.
        """
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and len(self.records()) <= self.seen:
            time.sleep(0.05)
        if len(self.records()) > self.seen:
            time.sleep(stray)
        fresh = self.records()[self.seen:]
        self.seen += len(fresh)
        return fresh


# ------------------------------------------------------------------ the device --

@dataclass
class Scenario:
    key: str
    label: str
    server: ServerConfig
    verify: int = 1
    expect: str = "established"          # established | failed | echo-broken
    allowed_groups: tuple[int, ...] = (0x001D, 0x0017)
    measured: bool = False               # feeds the P2-P4 judgement
    spike_only: bool = False


@dataclass
class Outcome:
    scenario: Scenario
    code: int = 0
    device: dict = field(default_factory=dict)
    server: list[dict] = field(default_factory=list)


def spike(rest: RestClient, route: str, params: dict) -> tuple[int, dict]:
    """One PUT to the spike route, classified before anything reads its fields."""
    code, _headers, body = rest.request("PUT", route, params=params,
                                        timeout=SPIKE_TIMEOUT, retries=1)
    if code == 404 and not body.strip():
        # MicroHttpServer answers a route nobody registered with exactly this:
        # execute_api_v1 finds no command and returns -1 (software/api/routes.cc,
        # execute_api_v1), no static file matches, and _NotFound writes
        # "HTTP/1.1 404 Not Found" with no body (httpd c-version/lib/middleware.c).
        raise RouteAbsent(f"PUT {route} answered HTTP 404 with an empty body: this firmware "
                          "has no TLS spike route (stock firmware, or built without it)")
    if code == 403:
        raise Failure(f"PUT {route} answered 403: the REST password was refused")
    text = body.decode("utf-8", "replace")
    if code == 400 and "does not have parameter" in text:
        raise Failure(f"PUT {route} exists but rejects this suite's parameter names "
                      f"{sorted(params)}: {text[:300]}")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise Failure(f"PUT {route} answered HTTP {code} with a body that is not JSON: "
                      f"{text[:200]!r}") from exc
    if not isinstance(data, dict):
        raise Failure(f"PUT {route} answered HTTP {code} with JSON that is not an object")
    return code, data


def run_scenario(rest: RestClient, args, server: Server, scenario: Scenario) -> Outcome:
    params = {"host": args.server_ip, "port": server.port, "sni": args.sni,
              "verify": scenario.verify, "ca": "test", "echo": args.echo_bytes}
    code, data = spike(rest, args.route, params)
    records = server.new_records(RECORD_WAIT)
    return Outcome(scenario, code, data, records)


def one_connection(outcome: Outcome) -> dict:
    if not outcome.server:
        raise Failure("the server logged no finished connection within "
                      f"{RECORD_WAIT:.0f}s of the device's reply: either the device never "
                      "connected, or its TCP connection is still open (spec section 3: the "
                      "socket is closed on every exit path)")
    if len(outcome.server) > 1:
        raise Failure(f"the server logged {len(outcome.server)} connections for one request "
                      f"(a silent retry or fallback): "
                      f"{[(r['conn'], r['handshake_ok'], r['app_in']) for r in outcome.server]}")
    record = outcome.server[0]
    if not record["fin"]:
        raise Failure(f"the TLS session ended ({record['close']}) but the device did not close "
                      "its TCP connection (spec section 3: the socket is closed on every exit "
                      "path)")
    if record["violations"]:
        raise Failure(f"the server's own sources disagree, so this connection proves "
                      f"nothing: {record['violations']}")
    return record


def judge_established(args, outcome: Outcome) -> list[str]:
    """Every way an ESTABLISHED report can disagree with the server. Empty is a pass."""
    device, scenario = outcome.device, outcome.scenario
    record = one_connection(outcome)
    problems = []
    if field_of(device, "ok") is not True:
        problems.append(f"device says ok={field_of(device, 'ok')!r}, stage "
                        f"{field_of(device, 'stage', False)!r}, error "
                        f"{field_of(device, 'error', False)!r}")
    if not record["handshake_ok"]:
        problems.append(f"the server saw no completed handshake: {record['error']}")
        return problems
    negotiated = record["negotiated"]
    if record["sni_wire"] != args.sni:
        problems.append(f"the ClientHello carried SNI {record['sni_wire']!r}, "
                        f"not {args.sni!r}")
    if negotiated["version"] != TLS13:
        problems.append(f"the server negotiated {negotiated['version']!r}, not TLS 1.3")
    if normalise_version(field_of(device, "tls_version")) != negotiated["version"]:
        problems.append(f"device reports version {field_of(device, 'tls_version')!r}; "
                        f"the ServerHello selected {negotiated['version']:#06x}")
    if normalise_cipher(field_of(device, "ciphersuite")) != negotiated["cipher_suite"]:
        problems.append(f"device reports cipher suite {field_of(device, 'ciphersuite')!r}; "
                        f"the ServerHello selected {negotiated['cipher_suite']:#06x}")
    if normalise_group(field_of(device, "group")) != negotiated["group"]:
        problems.append(f"device reports group {field_of(device, 'group')!r}; the "
                        f"ServerHello selected {negotiated['group']:#06x}")
    if negotiated["group"] not in scenario.allowed_groups:
        problems.append(f"the server selected group {negotiated['group']:#06x}, outside "
                        f"{[hex(g) for g in scenario.allowed_groups]}")
    n = args.echo_bytes
    if record["app_in"] != n:
        problems.append(f"the server received {record['app_in']} plaintext bytes, not {n}")
    if scenario.server.mangle == "none":
        if record["app_out"] != n or record["app_in_sha256"] != record["app_out_sha256"]:
            problems.append(f"the server echoed {record['app_out']} bytes that differ from "
                            "what it received")
        if field_of(device, "echo_ok") is not True:
            problems.append(f"device says echo_ok={field_of(device, 'echo_ok')!r}")
        for name in ("echo_sent", "echo_received"):
            if normalise_int(field_of(device, name)) != n:
                problems.append(f"device reports {name}={field_of(device, name)!r}, not {n}")
    if record["close"] not in ("close_notify", "eof"):
        problems.append(f"the connection ended with {record['close']!r}")
    problems += judge_timing(device, record)
    problems += judge_stats(device)
    return problems


def judge_timing(device: dict, record: dict) -> list[str]:
    problems = []
    handshake_ms = field_of(device, "handshake_ms")
    handshake_us = field_of(device, "handshake_us")
    steps = normalise_int(field_of(device, "steps"))
    if not isinstance(handshake_ms, int | float) or handshake_ms <= 0:
        problems.append(f"handshake_ms={handshake_ms!r} is not a positive number")
    if not isinstance(handshake_us, int | float) or handshake_us <= 0:
        problems.append(f"handshake_us={handshake_us!r} is not a positive number")
    if problems:
        return problems
    # The server saw the handshake from the first ClientHello byte to the
    # client's Finished. The Nios clock spans more than that (it also covers
    # the TCP connect), so a shorter device figure is not a measurement.
    if record["server_handshake_ms"] and handshake_ms + 5 < record["server_handshake_ms"]:
        problems.append(f"device handshake_ms={handshake_ms} is shorter than the "
                        f"{record['server_handshake_ms']} ms the server itself observed")
    if handshake_us / 1000 > handshake_ms * 1.05 + 5:
        problems.append(f"ESP32 handshake_us={handshake_us} exceeds the Nios wall clock "
                        f"handshake_ms={handshake_ms}")
    # A TLS 1.3 client cannot finish in fewer than two exchanges: the
    # ClientHello out, the server's flight in, then its own Finished out.
    if steps is None or steps < 2:
        problems.append(f"steps={field_of(device, 'steps')!r}: a TLS 1.3 handshake takes "
                        "at least 2")
    return problems


def judge_stats(device: dict) -> list[str]:
    problems = []
    for block in ("stats_before", "stats_after", "stats_peak"):
        stats = device.get(block)
        if not isinstance(stats, dict):
            problems.append(f"device JSON has no {block!r} object")
            continue
        missing = [k for k in STATS_KEYS if not isinstance(stats.get(k), int)]
        if missing:
            problems.append(f"{block} lacks integer {missing}")
    if not problems:
        before = field_of(device, "heap_free_before")
        peak = field_of(device, "heap_free_peak")
        if peak > before:
            problems.append(f"heap_free at peak ({peak}) is above heap_free before ({before})")
    return problems


def judge_failed(args, outcome: Outcome, manifest: dict) -> tuple[list[str], str | None]:
    """A must-fail case: FAILED at the handshake, no plaintext, for the named cause.

    Returns the problems and a warning. The warning is for a missing alert: the
    spec does not oblige the Nios to deliver the ESP32's last ciphertext, so its
    absence is reported rather than failed, and the cause is then attested by
    the device's error code alone.
    """
    device, scenario = outcome.device, outcome.scenario
    expected_alert = manifest["chains"][scenario.server.chain]["expected_alert"]
    record = one_connection(outcome)
    problems = []
    if field_of(device, "ok") is not False:
        problems.append(f"device says ok={field_of(device, 'ok')!r} for a certificate it "
                        "must reject")
    stage = str(field_of(device, "stage", False) or "")
    if "handshake" not in stage.lower():
        problems.append(f"device's failing stage is {stage!r}, not the handshake")
    state = field_of(device, "state", False)
    if state is not None and state not in (STATE_FAILED, "FAILED"):
        problems.append(f"device reports state {state!r}, not FAILED")
    error = field_of(device, "error", False)
    code = normalise_int(error)
    if code is not None:
        if abs(code) != abs(X509_CERT_VERIFY_FAILED):
            problems.append(f"device error {error!r} is not MBEDTLS_ERR_X509_CERT_VERIFY_FAILED "
                            "(-0x2700)")
    elif not (isinstance(error, str) and ("2700" in error or "VERIFY" in error.upper())):
        problems.append(f"device error {error!r} does not name a certificate verification "
                        "failure")
    if record["handshake_ok"]:
        problems.append("the server completed the handshake")
    if record["app_in"] or record["app_out"]:
        problems.append(f"plaintext crossed: the server received {record['app_in']} and "
                        f"echoed {record['app_out']} bytes")
    if record["sni_wire"] != args.sni:
        problems.append(f"the ClientHello carried SNI {record['sni_wire']!r}")
    finals = [h for h in record["wire"]["server_hellos"] if not h["hrr"]]
    if not finals:
        problems.append("the server never sent its ServerHello, so the failure came before "
                        "the certificate and says nothing about verification")
    warning = None
    alert = record["alert_from_client"]
    if alert is None:
        warning = (f"no alert reached the server (connection ended {record['close']!r}); "
                   f"expected {expected_alert}")
    elif alert != expected_alert:
        problems.append(f"the device rejected the certificate with {alert}, expected "
                        f"{expected_alert}: it failed, but for another reason")
    return problems, warning


def judge_echo_broken(args, outcome: Outcome) -> list[str]:
    """The server broke the echo on purpose; the device must notice."""
    device, scenario = outcome.device, outcome.scenario
    record = one_connection(outcome)
    problems = []
    n = args.echo_bytes
    if not record["handshake_ok"] or record["app_in"] != n:
        problems.append(f"the control did not reach its echo (handshake_ok="
                        f"{record['handshake_ok']}, received {record['app_in']} of {n})")
        return problems
    if record.get("mangled_at") != n - 1:
        problems.append(f"the server did not break byte {n - 1} "
                        f"(mangled_at={record.get('mangled_at')!r})")
    if field_of(device, "echo_ok") is not False:
        problems.append(f"the server {MANGLED[scenario.server.mangle]} the last echoed byte, "
                        f"and the device still says echo_ok={field_of(device, 'echo_ok')!r}")
    if field_of(device, "ok") is True:
        problems.append("device says ok=true for an echo that came back wrong")
    if record["close"] not in ("close_notify", "eof"):
        problems.append(f"the connection ended with {record['close']!r}")
    return problems


# ---------------------------------------------------------------- the fixtures --

def host_control(server: Server, sni: str, verify: bool, curve: str | None,
                 payload: bytes) -> tuple[bool, str, bytes]:
    """This machine's own TLS client against the server: the oracle's control."""
    import ssl
    context = ssl.create_default_context(cafile=str(server.pki_dir / "test-ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if curve:
        context.set_ecdh_curve(curve)
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=10) as raw, \
                context.wrap_socket(raw, server_hostname=sni) as tls:
            tls.sendall(payload)
            got = b""
            while len(got) < len(payload):
                chunk = tls.recv(65536)
                if not chunk:
                    break
                got += chunk
            return True, "", got
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc), b""


def check_fixtures(args, pki_dir: Path, log_dir: Path) -> dict:
    """Prove the certificates, the server and its policies before trusting them."""
    with check("fixtures: the PKI holds the five chains it claims to"):
        manifest = pki.generate(pki_dir)
        problems = pki.verify_fixtures(pki_dir)
        if problems:
            raise Failure("; ".join(problems))
        detail(f"test root sha256 {manifest['root_sha256']} ({pki_dir / 'test-ca.pem'}): "
               "the firmware under test must carry exactly this root")
    payload = bytes(range(256)) * (args.echo_bytes // 256 + 1)
    payload = payload[:args.echo_bytes]
    cases = [
        ("ecdsa", "both", "none", True, None, "established", None),
        ("rsa", "both", "none", True, None, "established", None),
        ("mismatch", "both", "none", True, None, "failed", pki.ALERT_BAD_CERT),
        ("expired", "both", "none", True, None, "failed", pki.ALERT_CERT_EXPIRED),
        ("untrusted", "both", "none", True, None, "failed", pki.ALERT_UNKNOWN_CA),
        ("mismatch", "both", "none", False, None, "established", None),
        ("ecdsa", "x25519", "none", True, "prime256v1", "refused", None),
        ("ecdsa", "p256", "none", True, "X25519", "refused", None),
        ("ecdsa", "p256", "none", True, None, "established", None),
        ("ecdsa", "both", "flip-last", True, None, "echo-broken", None),
    ]
    for chain, groups, mangle, verify, curve, want, alert in cases:
        label = (f"fixtures: host client, {chain} chain, groups {groups}, "
                 f"verify {'on' if verify else 'off'}"
                 f"{', client offers ' + curve + ' only' if curve else ''}"
                 f"{', echo ' + mangle if mangle != 'none' else ''}: {want}")
        with check(label):
            server = Server(ServerConfig(chain, groups, mangle), pki_dir,
                            log_dir / f"fixture-{chain}-{groups}-{mangle}.jsonl",
                            args.echo_bytes)
            server.start()
            try:
                ok, error, got = host_control(server, args.sni, verify, curve, payload)
                records = server.new_records(RECORD_WAIT, stray=0.2)
            finally:
                server.stop()
            if len(records) != 1:
                raise Failure(f"{len(records)} server records for one connection")
            record = records[0]
            if record["violations"]:
                raise Failure(f"server sources disagree: {record['violations']}")
            if want == "established" and not (ok and got == payload and record["handshake_ok"]
                                               and record["app_in_sha256"]
                                               == record["app_out_sha256"]):
                raise Failure(f"expected a clean echo: client {ok} {error!r}, server "
                              f"{record['handshake_ok']} {record['error']}")
            if want == "failed" and (ok or record["handshake_ok"]
                                     or record["alert_from_client"] != alert):
                raise Failure(f"expected {alert}: client {ok} {error!r}, server alert "
                              f"{record['alert_from_client']}")
            if want == "refused" and (ok or record["handshake_ok"]):
                raise Failure(f"the group policy {groups} let a client that offers only "
                              f"{curve} through: group "
                              f"{record['negotiated']['group']}")
            if want == "echo-broken" and (not ok or got == payload
                                          or record.get("mangled_at") != len(payload) - 1):
                raise Failure("the flip-last control did not change the echoed bytes")
    return manifest


# ------------------------------------------------------------------- the suite --

def scenarios(repeat: int) -> list[Scenario]:
    listed = [Scenario(f"a{i + 1}", f"a: ecdsa chain, verify on, run {i + 1} of {repeat}",
                       ServerConfig("ecdsa"), measured=True) for i in range(repeat)]
    listed += [Scenario(f"b{i + 1}", f"b: rsa chain, verify on, run {i + 1} of {repeat}",
                        ServerConfig("rsa"), measured=True) for i in range(repeat)]
    listed += [
        Scenario("c-x25519", "c: the server allows X25519 only",
                 ServerConfig("ecdsa", "x25519"), allowed_groups=(0x001D,)),
        Scenario("c-p256", "c: the server allows P-256 only",
                 ServerConfig("ecdsa", "p256"), allowed_groups=(0x0017,)),
        Scenario("echo-flip", "control: the server flips the last echoed byte",
                 ServerConfig("ecdsa", mangle="flip-last"), expect="echo-broken"),
        Scenario("echo-short", "control: the server withholds the last echoed byte",
                 ServerConfig("ecdsa", mangle="drop-last"), expect="echo-broken"),
        Scenario("d-mismatch", "d: hostname mismatch must fail at the handshake",
                 ServerConfig("mismatch"), expect="failed"),
        Scenario("d-untrusted", "d: an untrusted CA must fail at the handshake",
                 ServerConfig("untrusted"), expect="failed"),
        Scenario("d-expired", "d: an expired certificate must fail at the handshake",
                 ServerConfig("expired"), expect="failed"),
        Scenario("e-verify-off", "e: SPIKE-ONLY verify=0 against the mismatched host completes",
                 ServerConfig("mismatch"), verify=0, spike_only=True),
    ]
    return listed


def measurement(outcome: Outcome) -> dict:
    device = outcome.device
    record = outcome.server[0]
    return {
        "scenario": outcome.scenario.key,
        "chain": outcome.scenario.server.chain,
        "handshake_us": field_of(device, "handshake_us", False),
        "handshake_ms": field_of(device, "handshake_ms", False),
        "heap_free_before": field_of(device, "heap_free_before", False),
        "heap_free_after": field_of(device, "heap_free_after", False),
        "heap_free_peak": field_of(device, "heap_free_peak", False),
        "echo_ok": field_of(device, "echo_ok", False),
        "echo_intact_server": (record["app_in"] == record["app_out"]
                               and record["app_in_sha256"] == record["app_out_sha256"]),
        "server_handshake_ms": record["server_handshake_ms"],
        "tcp_in": record["tcp_in"], "tcp_out": record["tcp_out"],
        "steps": field_of(device, "steps", False),
        "group": record["negotiated"]["group"],
        "hrr": record["negotiated"]["hrr"],
    }


def run(args) -> tuple[bool, str]:
    pki_dir = pki.pki_dir(args.pki_dir)
    log_dir = Path(args.log_dir or tempfile.mkdtemp(prefix="tls-spike-"))
    log_dir.mkdir(parents=True, exist_ok=True)
    results_path = Path(args.results)
    failures: list[str] = []

    with check("predictions: the judge matches its registration"):
        opened = predictions.open_results(results_path)
        if opened["integrity_at_start"]:
            raise Failure("; ".join(opened["integrity_at_start"]))
        detail(f"results file {results_path} opened before the first device call, judge "
               f"sha256 {opened['judge_sha256_at_start']}")

    manifest = check_fixtures(args, pki_dir, log_dir)
    detail(f"server logs in {log_dir}")

    rest = RestClient(args.host, args.password or None, args.timeout)
    measured: list[dict] = []
    positives_ok = False
    selected = [s for s in scenarios(args.repeat)
                if not args.only or any(s.key.startswith(k) for k in args.only)]
    for number, scenario in enumerate(selected):
        server = Server(scenario.server, pki_dir, log_dir / f"{scenario.key}.jsonl",
                        args.echo_bytes)
        label = scenario.label
        started = time.monotonic()
        try:
            server.start()
            outcome = run_scenario(rest, args, server, scenario)
        except RouteAbsent as exc:
            check_start(f"f: PUT {args.route} is served (the spike route exists)")
            check_fail(str(exc))
            not_run = ", ".join(s.key for s in selected)
            return False, f"{exc}. Not run: {not_run}"
        except Failure as exc:
            check_start(label)
            check_fail(str(exc), elapsed=time.monotonic() - started)
            failures.append(f"{scenario.key}: {exc}")
            continue
        finally:
            server.stop()
        if number == 0:
            check_start(f"f: PUT {args.route} is served (the spike route exists)")
            check_ok(f"HTTP {outcome.code}", elapsed=time.monotonic() - started)

        warning = None
        try:
            if scenario.expect == "established":
                problems = judge_established(args, outcome)
            elif scenario.expect == "echo-broken":
                problems = judge_echo_broken(args, outcome)
            else:
                if not positives_ok:
                    problems = ["uninterpretable: no verify-on handshake with the test root "
                                "completed earlier in this run, so a failure here may be the "
                                "device failing everything"]
                    problems_extra, warning = judge_failed(args, outcome, manifest)
                    problems += problems_extra
                else:
                    problems, warning = judge_failed(args, outcome, manifest)
        except Failure as exc:
            problems = [str(exc)]
        elapsed = time.monotonic() - started
        check_start(label + (" [SPIKE-ONLY: verification off]" if scenario.spike_only else ""))
        if problems:
            for problem in problems[1:]:
                detail(problem)
            check_fail(problems[0], elapsed=elapsed)
            failures.append(f"{scenario.key}: {problems[0]}")
        elif warning:
            check_warn(warning, elapsed=elapsed)
        else:
            check_ok(passed_summary(outcome), elapsed=elapsed)
        # What the must-fail cases need from a positive case is proof that the
        # device trusts the test root: the server completed a verify-on
        # handshake with it. Whether the rest of that case passed is its own
        # verdict.
        if (scenario.verify and scenario.expect == "established" and len(outcome.server) == 1
                and outcome.server[0]["handshake_ok"]):
            positives_ok = True
        if scenario.measured and outcome.server and outcome.server[0]["handshake_ok"]:
            measured.append(measurement(outcome))

    leak_check(measured)
    p1 = json.loads(Path(args.p1_sizes).read_text()) if args.p1_sizes else None
    with check("predictions: judged by the registered code"):
        results = predictions.close_results(results_path,
                                            {"p1": p1, "runs": measured, "concurrent": None})
        detail(f"verdict: {results['verdict']}")
        for key in predictions.BANDS:
            entry = results["judgement"][key]
            detail(f"{key} {entry['status']}: value {entry['value']!r} {entry['unit']}, "
                   f"band {entry['band']}")
        if results["integrity_at_end"]:
            raise Failure(results["verdict"])
    if failures:
        return False, f"{len(failures)} scenario(s) failed; first: {failures[0]}"
    return True, f"{check_count()} checks; predictions: {results['verdict']}"


def passed_summary(outcome: Outcome) -> str:
    record = outcome.server[0]
    if outcome.scenario.expect == "failed":
        return f"rejected with {record['alert_from_client']}, 0 B of plaintext"
    if outcome.scenario.expect == "echo-broken":
        return (f"server {MANGLED[outcome.scenario.server.mangle]} byte "
                f"{record.get('mangled_at')}, device said echo_ok=false")
    return (f"TLS 1.3 {record['negotiated']['cipher_suite']:#06x}, group "
            f"{record['negotiated']['group']:#06x}"
            f"{' after HRR' if record['negotiated']['hrr'] else ''}, "
            f"{record['app_in']} B echoed")


def leak_check(measured: list[dict]) -> None:
    after = [m["heap_free_after"] for m in measured if isinstance(m["heap_free_after"], int)]
    if len(after) < 2:
        return
    check_start("heap_free after each session does not drift down")
    drop = after[0] - after[-1]
    detail(f"heap_free after each session: {after}")
    if drop > 2048:
        check_warn(f"{drop} bytes less free after the last session than after the first")
    else:
        check_ok(f"drift {drop} B over {len(after)} sessions")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    cli.add_device_arguments(parser, timeout=SPIKE_TIMEOUT)
    parser.add_argument("--route", default=ROUTE, help=f"the spike route (default {ROUTE})")
    parser.add_argument("--server-ip", help="this machine's address as the device reaches it "
                                            "(default: the source address of the route to it)")
    parser.add_argument("--sni", default=pki.SNI)
    parser.add_argument("--echo-bytes", type=int, default=DEFAULT_ECHO_BYTES)
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT,
                        help="runs of scenarios a and b, for the P2-P4 medians")
    parser.add_argument("--pki-dir", help="default $TLS_SPIKE_PKI, else .pki beside this file")
    parser.add_argument("--log-dir", help="where the server logs go (default: a new temp dir)")
    parser.add_argument("--results", default="tls_spike_results.json",
                        help="the results file, opened before the first device call")
    parser.add_argument("--p1-sizes", help="JSON from the budget lane: base_bin_bytes, "
                                           "tls_bin_bytes, full_bin_bytes, app_partition_bytes")
    parser.add_argument("--only", action="append",
                        help="run only scenarios whose key starts with this (repeatable)")
    args = parser.parse_args()
    if args.echo_bytes < 2:
        parser.error("--echo-bytes must be at least 2, so the controls have a last byte")
    if not args.server_ip:
        device = targets.device_of(args.host)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((device, 9))
            args.server_ip = probe.getsockname()[0]
        finally:
            probe.close()
    try:
        passed, summary = run(args)
    except Failure as exc:
        passed, summary = False, str(exc)
    except Exception as exc:  # noqa: BLE001
        passed, summary = False, format_exception(exc)
    if passed:
        suite_ok(SUITE, summary)
        return 0
    suite_fail(SUITE, summary)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
