#!/usr/bin/env python3
"""tlsb.py: shared helpers for the tls-bench lane (harness API only; no urllib/curl/ftplib).

Needs the c64-test-harness Python package (https://github.com/JC-000/c64-test-harness) in the interpreter, run isolated:
    python3 -I script.py ...
(-I drops the script directory from sys.path, so the scripts add this directory themselves.)

The one place a private harness call is used is `rest_call`: the Nios build's
PUT/GET /v1/machine:tls_bench and GET /v1/machine:heap have no public harness call.
Everything else is public API.
"""
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HOST = os.environ.get("TLSB_HOST")    # the Ultimate 64 under test; --host overrides
DEFAULT_PEER = os.environ.get("TLSB_PEER")    # address of the machine running the two peer servers; --peer overrides


def need_host(ap, host):
    if not host:
        ap.error("no device address: pass --host or set TLSB_HOST")
    return host


def count_lines(path):
    """JSON lines (starting with '{') in a peer log; 0 when the file is missing."""
    try:
        with open(path) as f:
            return sum(1 for ln in f if ln.startswith("{"))
    except OSError:
        return 0


def locked(host, fn):
    """fn() under the DeviceLock, or inside locked.py's lock when that holds it (same rule as route_probe.locked)."""
    from c64_test_harness.backends.device_lock import DeviceLock, device_lock_holder
    pid = os.environ.get("C64U_LOCK_PID")
    if pid:
        h = device_lock_holder(host)
        if h and str(h.get("pid")) == pid:
            return fn()
        sys.exit("refusing: C64U_LOCK_PID=%s is not the holder of the DeviceLock for %s (holder: %s)" % (pid, host, h))
    with DeviceLock(host, allow_nested=True):
        return fn()


def own_lock(host, fn):
    """FTP storage calls need THIS process to hold the DeviceLock (ultimate64_storage._session)."""
    from c64_test_harness.backends.device_lock import DeviceLock
    if os.environ.get("C64U_LOCK_PID"):
        sys.exit("refusing: FTP storage calls need their own lock; run outside the locked.py shell")
    with DeviceLock(host, allow_nested=True):
        return fn()


def client(host, timeout=10.0):
    from c64_test_harness.backends.ultimate64_client import Ultimate64Client
    return Ultimate64Client(host, timeout=timeout, warn_unlocked=False)


def rest_call(c, method, path, timeout_note=None):
    """THE private-harness call of this kit: method + path on the REST API, JSON answer.

    `c._request` is private; a public generic call is to be requested from the harness owner. Raises on a
    non-2xx status. Isolated here so the swap is one function.
    """
    status, data = c._request(method, path)
    if not 200 <= status < 300:
        raise RuntimeError("%s %s -> HTTP %d %r" % (method, path, status, data[:200]))
    return json.loads(data) if data else {}


def percentile95(sorted_values):
    """Barry's definition: values[int(0.95 * (n - 1))] on the sorted list."""
    return sorted_values[int(0.95 * (len(sorted_values) - 1))]


def summarise(values):
    """min/median/p95/max as tls_bench_collect.py; None for an empty or all-None list."""
    v = sorted(x for x in values if x is not None)
    if not v:
        return None
    return {"min": v[0], "median": statistics.median(v), "p95": percentile95(v), "max": v[-1]}


def latency_summary(samples):
    """tls_bench_latency.py's summary of a list of {elapsed_ms, error}."""
    ok = sorted(s["elapsed_ms"] for s in samples if s["error"] is None)
    return {"count": len(samples), "failures": len(samples) - len(ok),
            "median_ms": statistics.median(ok) if ok else None,
            "p95_ms": percentile95(ok) if ok else None,
            "max_ms": ok[-1] if ok else None}


def now_wall():
    return time.time()


PHI2 = {"pal": 985248.0, "ntsc": 1022727.0}
SYSMODE = ("U64 Specific Settings", "System Mode")


def phi2_for_mode(mode):
    """PHI2 Hz for a 'System Mode' value (PAL or NTSC; the device lists e.g. 'PAL' / 'NTSC')."""
    m = str(mode).strip()
    if m in ("PAL", "NTSC"):                 # exactly these: PAL-60 / NTSC-50 have other timings (color_timings.cc)
        return PHI2[m.lower()]
    raise ValueError("System Mode %r: only exactly PAL or NTSC have a known PHI2" % (mode,))


def read_phi2(c):
    """(phi2_hz, mode_text) from the device's System Mode: the CIA timebase is PHI2 of the video standard in use."""
    mode = c.get_config_value(*SYSMODE)
    return phi2_for_mode(mode), str(mode).strip()


READBACK_ITEMS = [("U64 Specific Settings", "Turbo Control"), ("U64 Specific Settings", "CPU Speed"),
                  ("U64 Specific Settings", "System Mode"), ("WiFi settings", "WiFi Enabled"),
                  ("U64 Specific Settings", "Badline Timing"), ("Network Settings", "SNTP Enable"), ("C64 and Cartridge Settings", "Command Interface")]


def config_readback(c):
    """What the device reports right now for the settings a leg depends on (recorded into every result JSON)."""
    out = {}
    for cat, item in READBACK_ITEMS:
        try:
            out["%s / %s" % (cat, item)] = str(c.get_config_value(cat, item)).strip()
        except Exception as exc:  # noqa: BLE001
            out["%s / %s" % (cat, item)] = "ERROR %s" % exc
    return out
