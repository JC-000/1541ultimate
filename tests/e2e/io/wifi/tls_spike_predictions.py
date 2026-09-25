#!/usr/bin/env python3
"""The registered predictions of the M2 TLS spike (spec section 5) and the code that judges them.

SPIKE CODE, not for upstream. FROZEN: this whole file is the judging code. Its
SHA-256 is written into tls_spike_predictions.json by `--register`, before the
first rig run, and that registry is committed with it. Every results file the
suite writes carries both hashes: the registered one, and the one of this file
as it stood when the run was judged. If they differ, the verdict is INVALID,
whatever the numbers were. A band is never moved after the fact; a result
outside it is reported as OUTSIDE.

The verdict is `verdict(judge(measurements))`: a function of the judgement,
not text written beside it.

Host load (amendment 7, M2-SPEC.md section 13): P2 is judged only when this
host's 1-minute load average stayed below 4 in every sample the suite took
(start, after each scenario, end). Otherwise, or with no samples, every P2
entry that has a value is "INCONCLUSIVE (host load)": never INSIDE or OUTSIDE.
The rule is conservative for P2a and P2b, which come from the ESP32's own
clock, and it is applied to them anyway, as the amendment says.

OPEN (amendment 9 H): handshake_ms starts before OPEN, and the reply has no
separate OPEN round trip, so P2c and P4b cannot exclude OPEN's work (CA parse,
DRBG seed, ssl_setup, psa_crypto_init on the first run). Their values are upper
bounds on the link overhead. Inside the band, the prediction holds a fortiori.
Outside it, the bound cannot decide, and the status is "INCONCLUSIVE (includes
OPEN)", never OUTSIDE.

P3a (amendment 9 F) is heap_free before minus stats_peak.heap_min_ever, the
low-water mark since this OPEN, so the handshake's transient peak is counted.

Registrations: f45d04dc (no host-load rule) was superseded by 4a60a005
(amendment 7), which amendment 9 (F, H, and the load samples) supersedes in
turn. Neither was used on a rig.

Units: 1 KB = 1024 bytes; times are milliseconds. Medians are taken over the
repeated runs of one scenario, and a median of an even count is the mean of
the middle two.
"""

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve()
REGISTRY = HERE.with_suffix(".json")

KB = 1024
STOCK_APP_PARTITION_BYTES = 0x100000

INSIDE = "INSIDE"
OUTSIDE = "OUTSIDE"
NOT_MEASURED = "NOT_MEASURED"
INCONCLUSIVE_LOAD = "INCONCLUSIVE (host load)"
INCONCLUSIVE_OPEN = "INCONCLUSIVE (includes OPEN)"
INCLUDES_OPEN_KEYS = ("P2c", "P4b")

LOAD_LIMIT = 4.0
HOST_LOAD_KEYS = ("P2a", "P2b", "P2c")

# id -> (statement, unit, low, high). None is an open end. For the boolean
# predictions low == high == the predicted value.
BANDS = {
    "P1a": ("TLS 1.3 client + X.509 + GCM + ChaCha20 + X25519/P-256 + ECDSA/RSA verify "
            "adds 120-200 KB to bridge.bin", "KB", 120, 200),
    "P1b": ("the full CA bundle adds another 50-80 KB", "KB", 50, 80),
    "P1c": ("the full configuration does NOT fit the stock 1 MB app partition",
            "fits", False, False),
    "P1d": ("a TLS-1.3-only build with a trimmed bundle or the test CA fits the stock "
            "1 MB app partition", "fits", True, True),
    "P2a": ("X25519 + ECDSA-P256 chain of 2: handshake 250-900 ms of ESP32 compute "
            "(median handshake_us of the ecdsa runs)", "ms", 250, 900),
    "P2b": ("the RSA-2048 chain adds 50-300 ms (median rsa - median ecdsa handshake_us)",
            "ms", 50, 300),
    "P2c": ("serial-link and LAN overhead add under 50 ms (median over the ecdsa runs of "
            "handshake_ms - handshake_us/1000; an upper bound, because it includes OPEN)",
            "ms", None, 50),
    "P3a": ("peak heap per session is 35-60 KB (the largest heap_free before - "
            "stats_peak.heap_min_ever over all established runs)", "KB", 35, 60),
    "P3b": ("two concurrent sessions leave at least 40 KB free with Wi-Fi running",
            "KB", 40, None),
    "P4a": ("100% of echo bytes intact (share of established runs whose echo the device "
            "and the server both show intact)", "%", 100, 100),
    "P4b": ("the handshake completes over the serial link within 2x the ESP32 compute "
            "time (median over the ecdsa runs of handshake_ms / (handshake_us/1000); an "
            "upper bound, because it includes OPEN)", "ratio", None, 2.0),
}


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _status(key: str, value) -> str:
    if value is None:
        return NOT_MEASURED
    _, _, low, high = BANDS[key]
    if isinstance(low, bool):
        return INSIDE if value == low else OUTSIDE
    if low is not None and value < low:
        return OUTSIDE
    if high is not None and value > high:
        return OUTSIDE
    # P2c's "under 50" is strict; every other band is closed.
    if key == "P2c" and value >= high:
        return OUTSIDE
    return INSIDE


def judge(measurements: dict) -> dict:
    """Each prediction's measured value and whether it lies in its band.

    `measurements` holds:
      p1: {base_bin_bytes, tls_bin_bytes, full_bin_bytes, app_partition_bytes}
          from the budget lane's builds; any may be missing.
      runs: one entry per established positive run (scenarios a and b), with
          chain, handshake_us, handshake_ms, heap_free_before, heap_min_ever_peak,
          echo_ok (device), echo_intact_server (server log).
      concurrent: {min_heap_free_two_sessions} if two sessions were measured.
      host_load: {start, end, samples}, this host's 1-minute load average, sampled
          at the start, after every scenario and at the end.
    """
    p1 = measurements.get("p1") or {}
    runs = measurements.get("runs") or []
    concurrent = measurements.get("concurrent") or {}
    values: dict[str, float | bool | None] = dict.fromkeys(BANDS)

    base, tls, full = (p1.get("base_bin_bytes"), p1.get("tls_bin_bytes"),
                       p1.get("full_bin_bytes"))
    partition = p1.get("app_partition_bytes") or STOCK_APP_PARTITION_BYTES
    if base is not None and tls is not None:
        values["P1a"] = (tls - base) / KB
    if tls is not None and full is not None:
        values["P1b"] = (full - tls) / KB
    if full is not None:
        values["P1c"] = full <= partition
    if tls is not None:
        values["P1d"] = tls <= partition

    def of(chain: str, key: str) -> list[float]:
        return [r[key] for r in runs if r.get("chain") == chain and r.get(key) is not None]

    ecdsa_us = of("ecdsa", "handshake_us")
    rsa_us = of("rsa", "handshake_us")
    if ecdsa_us:
        values["P2a"] = _median(ecdsa_us) / 1000
    if ecdsa_us and rsa_us:
        values["P2b"] = (_median(rsa_us) - _median(ecdsa_us)) / 1000
    paired = [(r["handshake_ms"], r["handshake_us"] / 1000) for r in runs
              if r.get("chain") == "ecdsa" and r.get("handshake_ms") is not None
              and r.get("handshake_us")]
    if paired:
        values["P2c"] = _median([wall - esp for wall, esp in paired])
        values["P4b"] = _median([wall / esp for wall, esp in paired])

    costs = [(r["heap_free_before"] - r["heap_min_ever_peak"]) / KB for r in runs
             if r.get("heap_free_before") is not None
             and r.get("heap_min_ever_peak") is not None]
    if costs:
        values["P3a"] = max(costs)
    if concurrent.get("min_heap_free_two_sessions") is not None:
        values["P3b"] = concurrent["min_heap_free_two_sessions"] / KB

    if runs:
        intact = [r for r in runs if r.get("echo_ok") is True and r.get("echo_intact_server")]
        values["P4a"] = 100.0 * len(intact) / len(runs)

    load = measurements.get("host_load") or {}
    samples = load.get("samples") or []
    quiet = bool(samples) and all(isinstance(x, int | float) and x < LOAD_LIMIT
                                  for x in samples)
    judgement = {}
    for key, (statement, unit, low, high) in BANDS.items():
        status = _status(key, values[key])
        if key in INCLUDES_OPEN_KEYS and status == OUTSIDE:
            status = INCONCLUSIVE_OPEN
        if key in HOST_LOAD_KEYS and status != NOT_MEASURED and not quiet:
            status = INCONCLUSIVE_LOAD
        judgement[key] = {"statement": statement, "unit": unit, "band": [low, high],
                          "value": values[key], "status": status}
    judgement["_informational"] = {
        "host_load": {"start": load.get("start"), "end": load.get("end"),
                      "max": max(samples) if samples else None, "samples": len(samples),
                      "limit": LOAD_LIMIT, "p2_judged": quiet},
        "ecdsa_handshake_us": ecdsa_us,
        "rsa_handshake_us": rsa_us,
        "p1_free_in_partition_kb": (partition - base) / KB if base is not None else None,
        "p3b_projection_kb": (
            (min(r["heap_free_before"] for r in runs if r.get("heap_free_before") is not None)
             / KB - 2 * max(costs)) if costs else None),
        "p3b_projection_note": "free before one session minus twice the worst session cost; "
                               "a projection, never judged",
    }
    return judgement


def verdict(judgement: dict) -> str:
    """One line, computed from the judgement alone."""
    groups: dict[str, list[str]] = {INSIDE: [], OUTSIDE: [], INCONCLUSIVE_LOAD: [],
                                    INCONCLUSIVE_OPEN: [], NOT_MEASURED: []}
    for key in BANDS:
        groups[judgement[key]["status"]].append(key)
    parts = [f"{status} {len(keys)}" + (f" ({', '.join(keys)})" if keys and status != INSIDE
                                        else "")
             for status, keys in groups.items()]
    return "; ".join(parts)


# ---------------------------------------------------------------- the registry --

def file_sha256() -> str:
    return hashlib.sha256(HERE.read_bytes()).hexdigest()


def git_head() -> str | None:
    result = subprocess.run(["git", "-C", str(HERE.parent), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() or None


def register() -> dict:
    registry = {
        "what": "M2 TLS spike registered predictions (spec section 5)",
        "registered_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "registered_on_commit": git_head(),
        "judge_file": HERE.name,
        "judge_sha256": file_sha256(),
        "bands": {key: {"statement": s, "unit": u, "band": [lo, hi]}
                  for key, (s, u, lo, hi) in BANDS.items()},
        "judge_source": HERE.read_text(),
    }
    REGISTRY.write_text(json.dumps(registry, indent=2) + "\n")
    return registry


def load_registry() -> dict:
    return json.loads(REGISTRY.read_text())


def integrity(registry: dict) -> list[str]:
    """Why this judge may not be used, or nothing if it may."""
    problems = []
    if registry.get("judge_sha256") != file_sha256():
        problems.append(f"{HERE.name} has changed since registration: registered "
                        f"{registry.get('judge_sha256')}, now {file_sha256()}")
    if registry.get("judge_source") != HERE.read_text():
        problems.append("the registered judge source differs from the file")
    registered_bands = {k: [v["statement"], v["unit"], *v["band"]]
                        for k, v in registry.get("bands", {}).items()}
    if registered_bands != {k: list(v) for k, v in BANDS.items()}:
        problems.append("the bands differ from the registered ones")
    return problems


def open_results(path: Path, host_load_start: float | None = None) -> dict:
    """Write the results file before the first device call: bands, code and hashes."""
    registry = load_registry()
    results = {
        "host_load_start": host_load_start,
        "registry": registry,
        "judge_sha256_at_start": file_sha256(),
        "integrity_at_start": integrity(registry),
        "run_started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "run in progress; nothing judged yet",
    }
    path.write_text(json.dumps(results, indent=2) + "\n")
    return results


def close_results(path: Path, measurements: dict) -> dict:
    """Judge, and write the judgement and the verdict computed from it."""
    results = json.loads(path.read_text())
    problems = integrity(results["registry"])
    judgement = judge(measurements)
    results.update({
        "host_load_end": (measurements.get("host_load") or {}).get("end"),
        "measurements": measurements,
        "judge_sha256_at_end": file_sha256(),
        "integrity_at_end": problems,
        "judgement": judgement,
        "verdict": ("INVALID: " + "; ".join(problems)) if problems else verdict(judgement),
        "run_ended_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "judged",
    })
    path.write_text(json.dumps(results, indent=2) + "\n")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--register", action="store_true",
                        help=f"write {REGISTRY.name} from this file (before the first rig run)")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 unless this file matches the registry")
    args = parser.parse_args()
    if args.register:
        registry = register()
        print(f"registered {registry['judge_sha256']}")
    if args.check or not args.register:
        problems = integrity(load_registry())
        for problem in problems:
            print(f"INVALID: {problem}", file=sys.stderr)
        if problems:
            return 1
        print(f"registry matches: {file_sha256()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
