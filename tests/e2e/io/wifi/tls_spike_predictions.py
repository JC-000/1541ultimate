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
            "handshake_ms - handshake_us/1000)", "ms", None, 50),
    "P3a": ("peak heap per session is 35-60 KB (the largest heap_free before - heap_free "
            "at peak over all established runs)", "KB", 35, 60),
    "P3b": ("two concurrent sessions leave at least 40 KB free with Wi-Fi running",
            "KB", 40, None),
    "P4a": ("100% of echo bytes intact (share of established runs whose echo the device "
            "and the server both show intact)", "%", 100, 100),
    "P4b": ("the handshake completes over the serial link within 2x the ESP32 compute "
            "time (median over the ecdsa runs of handshake_ms / (handshake_us/1000))",
            "ratio", None, 2.0),
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
          chain, handshake_us, handshake_ms, heap_free_before, heap_free_peak,
          echo_ok (device), echo_intact_server (server log).
      concurrent: {min_heap_free_two_sessions} if two sessions were measured.
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

    costs = [(r["heap_free_before"] - r["heap_free_peak"]) / KB for r in runs
             if r.get("heap_free_before") is not None and r.get("heap_free_peak") is not None]
    if costs:
        values["P3a"] = max(costs)
    if concurrent.get("min_heap_free_two_sessions") is not None:
        values["P3b"] = concurrent["min_heap_free_two_sessions"] / KB

    if runs:
        intact = [r for r in runs if r.get("echo_ok") is True and r.get("echo_intact_server")]
        values["P4a"] = 100.0 * len(intact) / len(runs)

    judgement = {}
    for key, (statement, unit, low, high) in BANDS.items():
        judgement[key] = {"statement": statement, "unit": unit, "band": [low, high],
                          "value": values[key], "status": _status(key, values[key])}
    judgement["_informational"] = {
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
    groups: dict[str, list[str]] = {INSIDE: [], OUTSIDE: [], NOT_MEASURED: []}
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


def open_results(path: Path) -> dict:
    """Write the results file before the first device call: bands, code and hashes."""
    registry = load_registry()
    results = {
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
