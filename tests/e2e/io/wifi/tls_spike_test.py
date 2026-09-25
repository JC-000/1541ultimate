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
import calendar
import hashlib
import json
import os
import re
import secrets
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

# The route and the reply are M2-SPEC.md section 7 (amendment 1), exactly, with
# time_source and esp_time from section 9 (amendment 3) and the group ruling of
# section 10 (amendment 4).
ROUTE = "/v1/machine:tlsspike"

# The device's JSON, field by field, and each field's type. A dotted key reads
# into a nested object.
FIELDS = {
    "ok": "ok",
    "stage": "stage",
    "error": "error",
    "handshake_ms": "handshake_ms",
    "handshake_us": "handshake_us",
    "tls_version": "tls_version",
    "ciphersuite": "ciphersuite",
    "group": "group",
    "echo_sent": "echo_sent",
    "echo_received": "echo_received",
    "echo_ok": "echo_ok",
    "steps": "steps",
    "time_source": "time_source",
    "esp_time": "esp_time",
    "heap_free_before": "stats_before.heap_free",
    "heap_free_after": "stats_after.heap_free",
    "heap_free_peak": "stats_peak.heap_free",
    "heap_min_ever_peak": "stats_peak.heap_min_ever",
    "stack_free_before": "stats_before.stack_free",
    "stack_free_after": "stats_after.stack_free",
    "stack_free_peak": "stats_peak.stack_free",
    "step_max_ms": "step_max_ms",
    "sessions_open_after": "sessions_open_after",
}
TYPES = {"ok": bool, "stage": str, "error": str, "handshake_ms": int, "handshake_us": int,
         "tls_version": int, "ciphersuite": int, "group": int, "echo_sent": int,
         "echo_received": int, "echo_ok": bool, "steps": int, "time_source": str,
         "esp_time": int, "step_max_ms": int, "sessions_open_after": int}
STATS_BLOCKS = ("stats_before", "stats_after", "stats_peak")
STATS_KEYS = ("heap_free", "heap_min_ever", "largest_block", "stack_free")
STAGES = ("connect", "open", "handshake", "echo", "close", "done")
TIME_SOURCES = ("nios", "sntp", "none")
# The section 9 refusal is "a distinct error text"; the text itself is the Nios
# lane's to choose, so the suite asks only that it speaks of time.
NO_TIME = re.compile(r"\b(time|clock)\b", re.IGNORECASE)
TIMED_OUT = re.compile(r"time\s*-?\s*out|timed\s+out", re.IGNORECASE)
# The device's clock may be off; this is only where a WARN starts.
CLOCK_SKEW_WARN_SECONDS = 86400
# mbedTLS 3.6.0 has no public getter for the negotiated group, so the device
# reports 0, meaning unknown (section 10). The group is taken from the server.
GROUP_UNKNOWN = 0

# mbedTLS returns this from the handshake for every certificate verification
# failure: the X.509 verify sets flags, and any flag makes it fail with
# MBEDTLS_ERR_X509_CERT_VERIFY_FAILED (-0x2700). Which flag it was travels in the
# alert, not in the code. The spec makes `error` free text, so the code is
# looked for in it rather than required.
X509_CERT_VERIFY_FAILED = -0x2700
ERROR_NUMBER = re.compile(r"-?0x[0-9a-fA-F]+|-?\b\d{3,}\b")

TLS13 = 0x0304
EXPIRED_NOT_AFTER = calendar.timegm(time.strptime(pki.EXPIRED_NOT_AFTER, "%Y%m%d%H%M%SZ"))

# The echo payload, generated on the Nios from (seed, n), recomputed here so the
# server's hash of what it received is checked against the spec, not against
# whatever the device says it sent.
PAYLOAD_MULTIPLIER = 2654435761
MAX_ECHO_BYTES = 4096


def expected_payload(seed: int, n: int) -> bytes:
    return bytes((((seed + i) * PAYLOAD_MULTIPLIER) & 0xFFFFFFFF) >> 24 & 0xFF
                 for i in range(n))


DEFAULT_ECHO_BYTES = 3000   # more than one 1024-byte step each way (spec section 2)
DEFAULT_REPEAT = 5
# One REST call has to outlast the firmware's own worst case, so that a slow run
# comes back as the device's timeout result rather than as "no answer". The
# limits are from the Nios lane's report (scratchpad/esp-tls/reports/m2-nios.md)
# and the adversarial review (m2-adversarial.md §7); this lane does not read the
# implementation. Each dedicated call may first spend about 0.7 s in its UNSENT
# retries (10 x (20 ms + 50 ms), adversarial §7), and one send can take about
# 10 s, because expiry is checked only after a partial send (adversarial §7):
#    1.7  STATS before              (m2-nios.md:27, STATS 1 s, + 0.7 retries)
#    5    TCP connect               (m2-nios.md:112, exit 4)
#    5.7  OPEN                      (:27, OPEN 5 s, + 0.7)
#   15    handshake deadline        (:118-119, exits 10-11)
#    5.7  + the STEP in flight      (:27, STEP 5 s, + 0.7; the deadline is checked after it)
#   10    + the send after it       (:116 exit 8, 5 s SO_SNDTIMEO, up to twice)
#    1.7  STATS after OPEN/peak     (:27, amendment 9 A)
#   30.8  echo, the same shape      (:120, exit 12, "as 10, 11": 15 + 5.7 + 10)
#    5.7  CLOSE                     (:27, CLOSE 5 s, + 0.7)
#    1.7  STATS after               (:27)
#   ----
#   83    s, as the adversarial review sums it. 90 s leaves about 7 s for the
#         REST round trip and the httpd queue.
SPIKE_TIMEOUT = 90.0
RECORD_WAIT = 10.0          # after the reply, for the server's connection record
STRAY_WAIT = 2.0            # after that, for a second connection nobody asked for
SERVER_IDLE_TIMEOUT = 120.0  # longer than one REST call, so an open socket shows
TIMING_SLACK_MS = 5
# Amendment 9 G: the Nios clock ticks every 5 ms and handshake_ms is two
# samples of it, so it can read up to a tick short; 10 ms covers both samples.
CLOCK_CROSSCHECK_SLACK_US = 10000
# Test hook for tls_spike_sim.py only: a load average to report instead of the
# host's, so the sim can show P2 judged and P2 held back. A run that uses it
# says so in its output and in the results file.
FAKE_LOAD_ENV = "TLS_SPIKE_FAKE_LOADAVG"


MANGLED = {"flip-last": "flipped", "drop-last": "withheld"}


class RouteAbsent(Failure):
    """The firmware has no spike route: the stock RED."""


def contract_problems(device: dict) -> list[str]:
    """Every way the reply departs from the section 7 names and types."""
    problems = []
    for name, kind in TYPES.items():
        value = device.get(FIELDS[name])
        # bool is an int in Python; an int field holding true is still wrong.
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            problems.append(f"{FIELDS[name]}={value!r} is not {kind.__name__}")
    for block in STATS_BLOCKS:
        stats = device.get(block)
        if not isinstance(stats, dict):
            problems.append(f"{block} is not an object")
            continue
        wrong = [k for k in STATS_KEYS
                 if not isinstance(stats.get(k), int) or isinstance(stats.get(k), bool)]
        if wrong:
            problems.append(f"{block} lacks integer {wrong}")
    if device.get("stage") not in STAGES:
        problems.append(f"stage {device.get('stage')!r} is not one of {STAGES}")
    if device.get("time_source") not in TIME_SOURCES:
        problems.append(f"time_source {device.get('time_source')!r} is not one of "
                        f"{TIME_SOURCES}")
    return problems


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
    seed: int = 0
    code: int = 0
    device: dict = field(default_factory=dict)
    server: list[dict] = field(default_factory=list)


def spike(rest: RestClient, route: str, params: dict, timeout: float) -> tuple[int, dict]:
    """One PUT to the spike route, classified before anything reads its fields.

    The route is not idempotent: every call opens a fresh TLS connection. A
    re-issued PUT would run the spike twice, and the server would log two
    connections, which the silent-fallback check fails. So it is sent once
    (retries=0: RestClient.request makes max(1, retries) attempts,
    tests/lib/rest.py:545), and no answer is reported as no answer.
    """
    try:
        code, _headers, body = rest.request("PUT", route, params=params,
                                            timeout=timeout, retries=0)
    except Failure as exc:
        raise Failure(f"no answer to PUT {route} within {timeout:.0f}s; not re-issued, "
                      f"because the route is not idempotent ({exc})") from exc
    return code, classify_reply(route, code, body, params)


def classify_reply(route: str, code: int, body: bytes, params: dict) -> dict:
    """The reply's JSON object, or the Failure that names what the answer means.

    Split from spike() so that the golden contract test (tls_spike_sim.py)
    classifies the Nios lane's recorded answers exactly as a rig run would.
    """
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
        raise Failure(f"PUT {route} answered HTTP 400: it exists but rejects this suite's "
                      f"parameter names {sorted(params)}: {text[:300]}")
    if code == 400:
        raise Failure(f"PUT {route} answered HTTP 400, a bad request from this suite's "
                      f"parameters {sorted(params)}: {text[:300]}")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise Failure(f"PUT {route} answered HTTP {code} with a body that is not JSON: "
                      f"{text[:200]!r}") from exc
    if not isinstance(data, dict):
        raise Failure(f"PUT {route} answered HTTP {code} with JSON that is not an object")
    return data


def run_scenario(rest: RestClient, args, server: Server, scenario: Scenario) -> Outcome:
    # A fresh seed per call, so a device that replays an earlier payload, or
    # ignores the seed, sends bytes whose hash matches nothing expected.
    seed = secrets.randbits(32)
    params = {"host": args.server_ip, "port": server.port, "sni": args.sni,
              "verify": scenario.verify, "ca": "test", "echo": args.echo_bytes, "seed": seed}
    code, data = spike(rest, args.route, params, args.spike_timeout)
    records = server.new_records(RECORD_WAIT)
    return Outcome(scenario, seed, code, data, records)


def payload_problems(args, outcome: Outcome, record: dict) -> list[str]:
    """What the server received, against the section 7 payload for (seed, n)."""
    expected = expected_payload(outcome.seed, args.echo_bytes)
    if record["app_in_sha256"] == hashlib.sha256(expected).hexdigest():
        return []
    return [f"the server received {record['app_in']} bytes that are not the payload for "
            f"seed={outcome.seed}, n={args.echo_bytes} (head {record['app_in_head']}, "
            f"expected {expected[:32].hex()})"]


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
    problems = contract_problems(device)
    if problems:
        return problems
    if device["ok"] is not True or device["stage"] != "done" or device["error"] != "":
        problems.append(f"device says ok={device['ok']!r}, stage {device['stage']!r}, "
                        f"error {device['error']!r}; a completed run is ok, done, \"\"")
    if not record["handshake_ok"]:
        problems.append(f"the server saw no completed handshake: {record['error']}")
        return problems
    negotiated = record["negotiated"]
    if record["sni_wire"] != args.sni:
        problems.append(f"the ClientHello carried SNI {record['sni_wire']!r}, "
                        f"not {args.sni!r}")
    if negotiated["version"] != TLS13:
        problems.append(f"the server negotiated {negotiated['version']!r}, not TLS 1.3")
    if device["tls_version"] != negotiated["version"]:
        problems.append(f"device reports version {field_of(device, 'tls_version')!r}; "
                        f"the ServerHello selected {negotiated['version']:#06x}")
    if device["ciphersuite"] != negotiated["cipher_suite"]:
        problems.append(f"device reports cipher suite {field_of(device, 'ciphersuite')!r}; "
                        f"the ServerHello selected {negotiated['cipher_suite']:#06x}")
    if device["group"] not in (GROUP_UNKNOWN, negotiated["group"]):
        problems.append(f"device reports group {device['group']!r}; the ServerHello "
                        f"selected {negotiated['group']:#06x} (0, unknown, would be accepted)")
    if negotiated["group"] not in scenario.allowed_groups:
        problems.append(f"the server selected group {negotiated['group']:#06x}, outside "
                        f"{[hex(g) for g in scenario.allowed_groups]}")
    n = args.echo_bytes
    if record["app_in"] != n:
        problems.append(f"the server received {record['app_in']} plaintext bytes, not {n}")
    problems += payload_problems(args, outcome, record)
    if scenario.server.mangle == "none":
        if record["app_out"] != n or record["app_in_sha256"] != record["app_out_sha256"]:
            problems.append(f"the server echoed {record['app_out']} bytes that differ from "
                            "what it received")
        if field_of(device, "echo_ok") is not True:
            problems.append(f"device says echo_ok={field_of(device, 'echo_ok')!r}")
        for name in ("echo_sent", "echo_received"):
            if device[name] != n:
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
    steps = field_of(device, "steps")
    if handshake_ms <= 0:
        problems.append(f"handshake_ms={handshake_ms!r} is not positive")
    if handshake_us <= 0:
        problems.append(f"handshake_us={handshake_us!r} is not positive")
    if problems:
        return problems
    # The device's two clocks are independent, and the Nios wall clock spans
    # the ESP32's compute, so it can never show less (amendment 7). This is the
    # load-proof guard on P2; the comparison with the server is only a WARN.
    if handshake_ms * 1000 < handshake_us - CLOCK_CROSSCHECK_SLACK_US:
        problems.append(f"the Nios clock (handshake_ms={handshake_ms}) is below the ESP32 "
                        f"clock (handshake_us={handshake_us}): one of them is wrong")
    # A TLS 1.3 client cannot finish in fewer than two exchanges: the
    # ClientHello out, the server's flight in, then its own Finished out.
    if steps < 2:
        problems.append(f"steps={field_of(device, 'steps')!r}: a TLS 1.3 handshake takes "
                        "at least 2")
    return problems


def timing_warning(outcome: Outcome) -> str | None:
    """A device figure shorter than the handshake the server itself watched.

    The server's window runs from the recv() that brought the first ClientHello
    byte to the recv() that brought the client's Finished, and the Nios clock
    spans more than that (it also covers the TCP connect). So a shorter device
    figure is not a measurement. It is a WARN, not a FAIL, because the server's
    window grows whenever the host schedules it late: in the offline sim, on a
    host at load average 57, honest 45-114 ms handshakes were watched as
    160-460 ms. Compare the rig host's load before reading much into one.
    """
    handshake_ms = outcome.device.get("handshake_ms")
    observed = outcome.server[0]["server_handshake_ms"]
    if isinstance(handshake_ms, int) and observed and handshake_ms + TIMING_SLACK_MS < observed:
        return (f"device handshake_ms={handshake_ms} is shorter than the {observed} ms the "
                "server itself observed (a made-up figure, or a busy host)")
    return None


def judge_stats(device: dict) -> list[str]:
    before = field_of(device, "heap_free_before")
    peak = field_of(device, "heap_free_peak")
    if peak > before:
        return [f"heap_free at peak ({peak}) is above heap_free before ({before})"]
    return []


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
    problems = contract_problems(device)
    if problems:
        return problems, None
    warning = None
    if device["ok"] is not False:
        problems.append(f"device says ok={device['ok']!r} for a certificate it must reject")
    if device["stage"] != "handshake":
        problems.append(f"the last stage the device reached is {device['stage']!r}, not "
                        "'handshake'")
    error = device["error"]
    numbers = [int(n, 0) for n in ERROR_NUMBER.findall(error)]
    if not error:
        problems.append("device reports a failure with an empty error")
    elif numbers and not any(abs(n) == abs(X509_CERT_VERIFY_FAILED) for n in numbers):
        problems.append(f"device error {error!r} carries {numbers}, not "
                        "MBEDTLS_ERR_X509_CERT_VERIFY_FAILED (-0x2700 = -9984)")
    elif not numbers and "verif" not in error.lower():
        warning = f"device error {error!r} names no code and no verification failure"
    if scenario.server.chain == "expired":
        # Expiry is only a fact relative to the clock the device verified with.
        if device["esp_time"] <= EXPIRED_NOT_AFTER:
            problems.append(f"uninterpretable: the device verified at esp_time="
                            f"{device['esp_time']}, which is not past the certificate's "
                            f"notAfter ({EXPIRED_NOT_AFTER}), so its rejection is not about "
                            "expiry")
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
    alert = record["alert_from_client"]
    if alert is None:
        warning = (f"no alert reached the server (connection ended {record['close']!r}); "
                   f"expected {expected_alert}")
    elif alert != expected_alert:
        problems.append(f"the device rejected the certificate with {alert}, expected "
                        f"{expected_alert}: it failed, but for another reason")
    return problems, warning


def refusal_kind(error: str) -> str | None:
    """'time' or 'entropy' for the two section 12 refusals, else None.

    A timeout is not a time refusal: "open timeout" must not read as "no
    trusted time", because the golden open_timeout reply would then pass as a
    correct refusal.
    """
    if "entropy" in error.lower():
        return "entropy"
    if NO_TIME.search(error) and not TIMED_OUT.search(error):
        return "time"
    return None


def judge_open_refused(outcome: Outcome) -> list[str]:
    """Verify on, and OPEN refused: no trustworthy time (section 9) or no entropy.

    The only correct behaviour is to refuse at OPEN, with an error that speaks
    of time, before any TLS byte leaves: never verify with a 1970 clock. The
    Nios may or may not have opened the TCP socket first, so zero connections
    or one that carried nothing are both right. When the rule holds, the
    scenario still cannot run, and that is reported as the rig precondition it
    is, never as a pass.
    """
    device = outcome.device
    problems = contract_problems(device)
    if device.get("ok") is not False or device.get("stage") != "open":
        problems.append(f"device says ok={device.get('ok')!r}, stage {device.get('stage')!r}; "
                        "with verify on and no trusted time it must fail at 'open'")
    error = str(device.get("error", ""))
    kind = refusal_kind(error)
    if kind is None:
        # Not a refusal at all (an OPEN timeout, a module error): the scenario
        # failed, and nothing says the device broke the fail-closed rule.
        return [f"OPEN failed without a section 12 refusal: {error!r}", *problems]
    no_entropy = kind == "entropy"
    if device.get("time_source") != "none" and not no_entropy:
        problems.append(f"OPEN refused for time, but time_source is "
                        f"{device.get('time_source')!r}")
    for record in outcome.server:
        if record["wire"]["client_hellos"] or record["tcp_in"]:
            problems.append(f"the server received {record['tcp_in']} bytes (a ClientHello: "
                            f"{bool(record['wire']['client_hellos'])}) from a device with no "
                            "trusted time")
        if not record["fin"]:
            problems.append("the device left its TCP connection open after refusing")
    if len(outcome.server) > 1:
        problems.append(f"the server logged {len(outcome.server)} connections")
    if problems:
        return ["fail-closed rule broken (section 9): " + problems[0], *problems[1:]]
    if no_entropy:
        return ["precondition: the ESP32 has no entropy source and correctly refused at OPEN "
                "(spec section 2), so this scenario could not run"]
    return ["precondition: the device has no trusted time (time_source 'none') and correctly "
            "refused at OPEN (section 9 held), so this verify-on scenario could not run; give "
            "the Nios a clock (RTC or SNTP) and rerun"]


def judge_outcome(args, outcome: Outcome, manifest: dict,
                  positives_ok: bool) -> tuple[list[str], str | None]:
    """One scenario's problems and warning, from the device's reply and the server log.

    A pure function of its inputs, so the golden contract test in
    tls_spike_sim.py feeds the Nios lane's real route output through exactly
    the judgement a rig run uses.
    """
    scenario, device = outcome.scenario, outcome.device
    warning = None
    try:
        open_refused = device.get("stage") == "open" and device.get("ok") is False
        # A no-entropy refusal applies whatever verify says (spec section 2);
        # the no-time refusal only with verify on (section 9).
        if open_refused and (scenario.verify
                             or refusal_kind(str(device.get("error", ""))) == "entropy"):
            problems = judge_open_refused(outcome)
        elif scenario.verify and device.get("time_source") == "none":
            # Amendment 9 A: the time fields come from a STATS right after a
            # successful OPEN, so "none" past OPEN means either the device went
            # on to verify with no trusted time, or that STATS was not taken.
            problems = [f"time_source 'none' past OPEN (stage {device.get('stage')!r}): "
                        "either the device verified without trusted time (the section 9 "
                        "fail-closed rule) or its STATS after OPEN was not taken "
                        "(amendment 9 A)"]
        elif scenario.expect == "established":
            problems = judge_established(args, outcome)
            warning = None if problems else (timing_warning(outcome)
                                             or clock_warning(outcome))
        elif scenario.expect == "echo-broken":
            problems = judge_echo_broken(args, outcome)
        elif not positives_ok:
            problems, warning = judge_failed(args, outcome, manifest)
            problems = ["uninterpretable: no verify-on handshake with the test root "
                        "completed earlier in this run, so a failure here may be the "
                        "device failing everything", *problems]
        else:
            problems, warning = judge_failed(args, outcome, manifest)
    except Failure as exc:
        problems = [str(exc)]
    # Amendment 9 D: every exit path closes its ESP32 session. A firmware that
    # never CLOSEs would otherwise pass, the heap drift being only a WARN.
    left = device.get("sessions_open_after")
    if isinstance(left, int) and not isinstance(left, bool) and left != 0:
        problems.append(f"sessions_open_after={left}: the run left an ESP32 session open "
                        "(amendment 9 D)")
    return problems, warning


def clock_warning(outcome: Outcome) -> str | None:
    """The device's esp_time far from this host's clock: reported, not failed."""
    esp_time = outcome.device.get("esp_time")
    if outcome.device.get("time_source") == "none" or not isinstance(esp_time, int):
        return None
    skew = esp_time - time.time()
    if abs(skew) > CLOCK_SKEW_WARN_SECONDS:
        return (f"esp_time={esp_time} is {skew / 86400:+.1f} days from this host's clock "
                f"(time_source {outcome.device.get('time_source')!r})")
    return None


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
    problems += payload_problems(args, outcome, record)
    if record.get("mangled_at") != n - 1:
        problems.append(f"the server did not break byte {n - 1} "
                        f"(mangled_at={record.get('mangled_at')!r})")
    problems += contract_problems(device)
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


def host_load(quiet: bool = False) -> float:
    """This host's 1-minute load average, the input to amendment 7's P2 rule.

    Sampled at the start, after every scenario and at the end, so "below 4
    throughout" is judged on the whole run, not on its two ends.
    """
    fake = os.environ.get(FAKE_LOAD_ENV)
    if fake is not None:
        if not quiet:
            detail(f"host load average FAKED as {fake} via ${FAKE_LOAD_ENV} (simulation only)")
        return float(fake)
    return os.getloadavg()[0]


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


def measurement(args, outcome: Outcome) -> dict:
    device = outcome.device
    record = outcome.server[0]
    return {
        "seed": outcome.seed,
        "echo_payload_matches_seed": not payload_problems(args, outcome, record),
        "stack_free_peak": field_of(device, "stack_free_peak", False),
        "esp_time": field_of(device, "esp_time", False),
        "time_source": field_of(device, "time_source", False),
        "scenario": outcome.scenario.key,
        "chain": outcome.scenario.server.chain,
        "handshake_us": field_of(device, "handshake_us", False),
        "handshake_ms": field_of(device, "handshake_ms", False),
        "heap_free_before": field_of(device, "heap_free_before", False),
        "heap_free_after": field_of(device, "heap_free_after", False),
        "heap_free_peak": field_of(device, "heap_free_peak", False),
        "heap_min_ever_peak": field_of(device, "heap_min_ever_peak", False),
        "stack_free_before": field_of(device, "stack_free_before", False),
        "stack_free_after": field_of(device, "stack_free_after", False),
        "step_max_ms": field_of(device, "step_max_ms", False),
        "echo_ok": field_of(device, "echo_ok", False),
        # Intact per the server: it received the section 7 payload for this
        # seed, and echoed exactly that.
        "echo_intact_server": (not payload_problems(args, outcome, record)
                               and record["app_in"] == record["app_out"]
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
        load_start = host_load()
        load_samples = [load_start]
        opened = predictions.open_results(results_path, load_start)
        if opened["integrity_at_start"]:
            raise Failure("; ".join(opened["integrity_at_start"]))
        detail(f"results file {results_path} opened before the first device call, judge "
               f"sha256 {opened['judge_sha256_at_start']}; host load {load_start:.2f} "
               f"(P2 is judged only below {predictions.LOAD_LIMIT})")

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
            if args.expect_spike:
                # A spike build made without a clean after toggling TLS_SPIKE
                # answers exactly like stock, so on a GREEN attempt the empty
                # 404 means the wrong image, not missing work.
                exc = Failure(f"the image was expected to carry the spike route (TLS_SPIKE=1 "
                              f"clean build) but answers 404: a stale or wrong image ({exc})")
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

        load_samples.append(host_load(quiet=True))
        problems, warning = judge_outcome(args, outcome, manifest, positives_ok)
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
        if (scenario.measured and len(outcome.server) == 1
                and outcome.server[0]["handshake_ok"]):
            measured.append(measurement(args, outcome))

    leak_check(measured)
    p1 = json.loads(Path(args.p1_sizes).read_text()) if args.p1_sizes else None
    with check("predictions: judged by the registered code"):
        load_end = host_load()
        load = {"start": load_start, "end": load_end, "samples": [*load_samples, load_end],
                "faked": os.environ.get(FAKE_LOAD_ENV) is not None}
        results = predictions.close_results(results_path,
                                            {"p1": p1, "runs": measured, "concurrent": None,
                                             "host_load": load})
        detail(f"host load {load['start']:.2f} at start, {load['end']:.2f} at end, "
               f"{max(load['samples']):.2f} at most over {len(load['samples'])} samples")
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
    return (f"TLS 1.3 {record['negotiated']['cipher_suite']:#06x}, server group "
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
    stacks = [m[k] for m in measured
              for k in ("stack_free_before", "stack_free_peak", "stack_free_after")
              if isinstance(m[k], int)]
    if stacks:
        detail(f"dispatcher stack_free (section 10, counts against P3): lowest {min(stacks)} B "
               f"over {len(measured)} sessions")
    steps = [m["step_max_ms"] for m in measured if isinstance(m["step_max_ms"], int)]
    if steps:
        detail(f"longest single STEP round trip (amendment 9 C, the worst dispatcher block): "
               f"{max(steps)} ms")
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
    parser.add_argument("--spike-timeout", type=float, default=SPIKE_TIMEOUT,
                        help=f"seconds to wait for one spike PUT (default {SPIKE_TIMEOUT:.0f}, "
                             "above the firmware's own worst case); the sim lowers it")
    parser.add_argument("--expect-spike", action="store_true",
                        help="the image under test was built with TLS_SPIKE=1 (GREEN runs): "
                             "an empty 404 then means a stale or wrong image, not stock")
    parser.add_argument("--only", action="append",
                        help="run only scenarios whose key starts with this (repeatable)")
    args = parser.parse_args()
    if not 2 <= args.echo_bytes <= MAX_ECHO_BYTES:
        parser.error(f"--echo-bytes must be 2-{MAX_ECHO_BYTES}: the spec caps echo at "
                     f"{MAX_ECHO_BYTES}, and the controls need a last byte")
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
