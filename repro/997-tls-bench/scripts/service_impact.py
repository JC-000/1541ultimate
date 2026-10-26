#!/usr/bin/env python3
"""service_impact.py: what a TLS run costs the rest of the Ultimate, for any image that serves PUT/GET /v1/machine:tls_bench
(Barry's Nios TLS image and the ESP32-offload responder image both do; `--build nios` is the load generator for both).

    python3 -I service_impact.py L --host <device> --build nios --out L.json --peer-plain-log <dir>/peer-plain.jsonl
    python3 -I service_impact.py F --host <device> --build nios --out F.json --peer-plain-log <dir>/peer-plain.jsonl
    python3 -I service_impact.py stage --host <device>   # put the 4 MiB file on /USB1/tlsbench/ftp4m.bin once, record its sha256
    python3 -I service_impact.py selftest                # offline checks with a fake device
(--host defaults to $TLSB_HOST.)

L: REST latency. Idle baseline (30 x get_info at 0.5 s, 5 s timeout), then BUSY for a fixed wall time (180 s) with the
   image's back-to-back TLS runs going and get_info every 0.5 s. Output in Barry's nios-latency.json shape
   (idle, busy, run, summary) plus per-sample wall/monotonic times and a `phase` tag (idle|busy); `capture_phase.py`
   adds the finer phase from the capture (tcp+hs / client_compute / transfer / plain / gap).
F: FTP throughput. 10 x storage_get_file of the staged 4 MiB file idle, then the same back to back for 180 s busy.
   Per download: start/end wall, bytes, sha256 ok, KiB/s, phase tag.

Load generator: PUT /v1/machine:tls_bench, re-PUT when the plain peer log shows a new line (or every --retrigger s as a
fallback; a PUT during a run answers `busy`). Harness `_request` through tlsb.rest_call.
The loop keeps going for the whole busy window; the final run is allowed to finish after the window (outside it).
L and F never run together.
"""
import argparse
import hashlib
import json
import os
import random
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tlsb  # noqa: E402

FTP_PATH = "/USB1/tlsbench/ftp4m.bin"
FTP_BYTES = 4 * 1024 * 1024
SHA_FILE = os.path.join(HERE, "ftp4m.sha256")


# ---------------------------------------------------------------- the pieces, all injectable for the selftest
class Window:
    """Wall + monotonic clock of one phase; every sample is stamped relative to the busy start."""

    def __init__(self):
        self.mono0 = time.monotonic()
        self.wall0 = time.time()

    def stamp(self, s):
        s["t_wall"] = round(time.time(), 3)
        s["since_start_ms"] = round((time.monotonic() - self.mono0) * 1000)
        return s


def probe_once(get_info, timeout_note=None):
    """One get_info timed like Barry's sample(): {elapsed_ms, error}."""
    started = time.monotonic()
    try:
        info = get_info()
        assert isinstance(info, dict) and info, "empty /v1/info"
        error = None
    except Exception as exc:  # noqa: BLE001 - the error text IS the datum
        error = "%s: %s" % (type(exc).__name__, exc)
    return {"elapsed_ms": round((time.monotonic() - started) * 1000, 3), "error": error}


def run_probes(get_info, *, count=None, seconds=None, interval=0.5, phase="idle", stop=None):
    """get_info every `interval` s on a fixed schedule (not drift-accumulating), for `count` samples or `seconds`."""
    out = []
    w = Window()
    next_t = time.monotonic()
    while True:
        if count is not None and len(out) >= count:
            break
        if seconds is not None and time.monotonic() - w.mono0 >= seconds:
            break
        if stop is not None and stop.is_set():
            break
        s = w.stamp(probe_once(get_info))
        s["phase"] = phase
        out.append(s)
        next_t += interval
        delay = next_t - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_t = time.monotonic()      # a slow sample does not trigger a burst afterwards
    return out


# ---------------------------------------------------------------- load generators
class NiosLoad:
    """Back-to-back Barry runs through PUT /v1/machine:tls_bench."""

    def __init__(self, rest, *, plain_log=None, retrigger=2.0, repeat=0.5):
        self.repeat = repeat
        self.rest = rest                       # rest(method) -> dict, on its own client/thread
        self.plain_log = plain_log
        self.retrigger = retrigger
        self.stop_ev = threading.Event()
        self.thread = None
        self.puts = []                         # {t_wall, state}
        self.final = None

    def _lines(self):
        if not self.plain_log:
            return 0
        try:
            with open(self.plain_log) as f:
                return sum(1 for ln in f if ln.startswith("{"))
        except OSError:
            return 0

    def _put(self):
        t = time.time()
        try:
            r = self.rest("PUT")
            state = r.get("state")
        except Exception as exc:  # noqa: BLE001
            state = "error: %s" % exc
        self.puts.append({"t_wall": round(t, 3), "state": state})
        return state

    def start(self):
        self.base_lines = self._lines()
        first = self._put()

        def loop():
            # The plain peer logs its line after sendall(), while the Nios is still reading ~128 KB: a PUT right then
            # answers `busy`. So after each new peer line keep re-PUTting every `repeat` s until one answers `running`.
            seen = self.base_lines
            pending = first != "running"
            last_put = time.monotonic()
            while not self.stop_ev.wait(self.repeat):
                n = self._lines()
                if n > seen:
                    seen = n
                    pending = True
                if not self.plain_log and time.monotonic() - last_put >= self.retrigger:
                    pending = True
                if pending:
                    last_put = time.monotonic()
                    if self._put() == "running":
                        pending = False
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop(self, finish_timeout=120.0):
        self.stop_ev.set()
        if self.thread:
            self.thread.join(5)
        # let the last run finish (outside the window) and fetch its record
        deadline = time.monotonic() + finish_timeout
        while time.monotonic() < deadline:
            try:
                r = self.rest("GET")
            except Exception as exc:  # noqa: BLE001
                r = {"state": "error", "error": str(exc)}
            if r.get("state") in ("complete", "idle", "error"):
                self.final = r
                break
            time.sleep(1.0)
        return self.final

    def describe(self):
        runs_started = sum(1 for p in self.puts if p["state"] == "running")
        return {"build": "nios", "puts": len(self.puts), "runs_started": runs_started,
                "busy_answers": sum(1 for p in self.puts if p["state"] == "busy"), "final_run": self.final}


# ---------------------------------------------------------------- L and F
def series_L(get_info, load, *, idle_n=30, busy_s=180.0, interval=0.5):
    idle = run_probes(get_info, count=idle_n, interval=interval, phase="idle")
    load.start()
    busy = run_probes(get_info, seconds=busy_s, interval=interval, phase="busy")
    window_end = time.time()
    run = load.stop()
    desc = load.describe()
    need = None
    if desc["build"] == "nios":
        need = max(1, int(busy_s / 45.0) - 1)          # a Nios run takes ~45 s; fewer starts = the load stalled
        desc["runs_started_needed"] = need
        desc["load_ok"] = desc["runs_started"] >= need
    return {"idle": idle, "busy": busy, "run": run,
            "summary": {"idle": tlsb.latency_summary(idle), "busy": tlsb.latency_summary(busy)},
            "load": desc, "window": {"busy_end_wall": window_end, "busy_seconds": busy_s,
                                                "interval_s": interval, "probe_timeout_s": 5}}


def download(get_file, expect_sha):
    t0 = time.time()
    m0 = time.monotonic()
    try:
        data = get_file()
        err = None
    except Exception as exc:  # noqa: BLE001
        data, err = b"", "%s: %s" % (type(exc).__name__, exc)
    dt = time.monotonic() - m0
    ok = err is None and hashlib.sha256(data).hexdigest() == expect_sha
    return {"start_wall": round(t0, 3), "end_wall": round(t0 + dt, 3), "elapsed_s": round(dt, 3), "bytes": len(data),
            "sha_ok": ok, "kib_s": round(len(data) / 1024 / dt, 1) if dt > 0 and not err else None, "error": err}


def f_summary(rows):
    ok = [r for r in rows if r["sha_ok"]]
    return {"count": len(rows), "failures": len(rows) - len(ok), "kib_s": tlsb.summarise([r["kib_s"] for r in ok])}


def series_F(get_file, expect_sha, load, *, idle_n=10, busy_s=180.0):
    idle = []
    for _ in range(idle_n):
        r = download(get_file, expect_sha)
        r["phase"] = "idle"
        idle.append(r)
    load.start()
    busy = []
    t0 = time.monotonic()
    while time.monotonic() - t0 < busy_s:
        r = download(get_file, expect_sha)
        r["phase"] = "busy"
        busy.append(r)
    window_end = time.time()
    run = load.stop()
    desc = load.describe()
    if desc["build"] == "nios":
        desc["runs_started_needed"] = max(1, int(busy_s / 45.0) - 1)
        desc["load_ok"] = desc["runs_started"] >= desc["runs_started_needed"]
    return {"idle": idle, "busy": busy, "run": run, "summary": {"idle": f_summary(idle), "busy": f_summary(busy)},
            "load": desc, "window": {"busy_end_wall": window_end, "busy_seconds": busy_s},
            "file": {"path": FTP_PATH, "bytes": FTP_BYTES, "sha256": expect_sha}}


# ---------------------------------------------------------------- real-device glue
def make_load(a, host):
    def rest(method):
        c2 = tlsb.client(host, timeout=a.timeout)       # own client: the trigger thread never shares one
        return tlsb.rest_call(c2, method, "/v1/machine:tls_bench")
    return NiosLoad(rest, plain_log=a.peer_plain_log, retrigger=a.retrigger)


def staged_sha():
    try:
        return open(SHA_FILE).read().split()[0]
    except OSError:
        sys.exit("no %s: run `stage` first" % SHA_FILE)


def cmd_stage(a):
    from c64_test_harness import storage_put_file, storage_get_file
    rng = random.Random(0x997)
    data = bytes(rng.getrandbits(8) for _ in range(FTP_BYTES))
    sha = hashlib.sha256(data).hexdigest()
    if a.dry_run:
        print("dry run: would put %d bytes sha256 %s to %s" % (len(data), sha, FTP_PATH))
        return
    tlsb.own_lock(a.host, lambda: storage_put_file(a.host, FTP_PATH, data, overwrite=True, verify=True))
    back = tlsb.own_lock(a.host, lambda: storage_get_file(a.host, FTP_PATH))
    if hashlib.sha256(back).hexdigest() != sha:
        sys.exit("STOP: read-back sha256 differs")
    open(SHA_FILE, "w").write("%s  ftp4m.bin\n" % sha)
    print("staged", FTP_PATH, sha)


def cmd_L(a):
    host = a.host
    c = tlsb.client(host, timeout=5.0)
    if a.dry_run:
        print(json.dumps(probe_once(c.get_info)))
        return 0
    load = make_load(a, host)
    def work():
        r = series_L(c.get_info, load, idle_n=a.idle_n, busy_s=a.busy_s, interval=a.interval)
        r["config_readback"] = tlsb.config_readback(c)          # inside the DeviceLock
        return r
    res = tlsb.locked(host, work)
    res["meta"] = {"build": a.build, "host": host, "label": a.label, "started": time.time()}
    if a.cfg:
        res["config_set_record"] = json.load(open(a.cfg))
    json.dump(res, open(a.out, "w"), indent=2)
    print(json.dumps(res["summary"], indent=2))
    if res["load"].get("load_ok") is False:
        print("LOAD STALLED: %s runs started, %s needed in the busy window; series not valid" % (
            res["load"]["runs_started"], res["load"]["runs_started_needed"]), file=sys.stderr)
        return 4
    return 0


def cmd_F(a):
    from c64_test_harness import storage_get_file
    host = a.host
    if a.dry_run:
        c = tlsb.client(host, timeout=5.0)
        print(json.dumps(probe_once(c.get_info)))
        return 0
    sha = staged_sha()
    load = make_load(a, host)
    def work():
        r = series_F(lambda: storage_get_file(host, FTP_PATH), sha, load, idle_n=a.idle_n, busy_s=a.busy_s)
        r["config_readback"] = tlsb.config_readback(tlsb.client(host, timeout=a.timeout))   # inside the DeviceLock
        return r
    res = tlsb.own_lock(host, work)
    res["meta"] = {"build": a.build, "host": host, "label": a.label, "started": time.time()}
    if a.cfg:
        res["config_set_record"] = json.load(open(a.cfg))
    json.dump(res, open(a.out, "w"), indent=2)
    print(json.dumps(res["summary"], indent=2))
    if res["load"].get("load_ok") is False:
        print("LOAD STALLED: %s runs started, %s needed in the busy window; series not valid" % (
            res["load"]["runs_started"], res["load"]["runs_started_needed"]), file=sys.stderr)
        return 4
    return 0


# ---------------------------------------------------------------- selftest (fake device, compressed time)
def selftest():
    import tempfile
    calls = {"info": 0}

    def get_info():
        calls["info"] += 1
        time.sleep(0.002)
        if calls["info"] == 7:
            raise TimeoutError("boom")
        return {"product": "fake"}

    states = {"n": 0}
    log = tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl")

    def rest(method):
        if method == "PUT":
            states["n"] += 1
            return {"state": "running"} if states["n"] % 2 else {"state": "busy"}
        return {"state": "complete", "error": 0}

    load = NiosLoad(rest, plain_log=log.name, repeat=0.05)
    stop = threading.Event()

    def feeder():     # the plain peer logs a line every 0.3 s
        while not stop.wait(0.3):
            log.write("{}\n")
            log.flush()
    threading.Thread(target=feeder, daemon=True).start()
    res = series_L(get_info, load, idle_n=5, busy_s=2.0, interval=0.1)
    stop.set()
    assert len(res["idle"]) == 5 and 15 <= len(res["busy"]) <= 21, len(res["busy"])
    assert all(s["phase"] == "idle" for s in res["idle"]) and all(s["phase"] == "busy" for s in res["busy"])
    fails = [s for s in res["idle"] + res["busy"] if s["error"]]
    assert len(fails) == 1 and "TimeoutError" in fails[0]["error"]
    assert res["summary"]["idle"]["count"] == 5 and res["summary"]["busy"]["failures"] + res["summary"]["idle"]["failures"] == 1
    assert res["load"]["runs_started"] >= 3 and res["load"]["puts"] >= 5, res["load"]
    assert res["run"]["state"] == "complete"
    assert res["load"]["runs_started"] >= 3 and res["load"]["busy_answers"] >= 1       # busy answers did not stall it
    assert res["load"]["load_ok"] is False or res["load"]["runs_started"] >= res["load"]["runs_started_needed"]
    # a Nios that answers busy for 3 PUTs after every peer line still gets re-PUT until running
    seq = {"n": 0}
    def rest3(method):
        if method == "PUT":
            seq["n"] += 1
            return {"state": "busy"} if seq["n"] % 4 else {"state": "running"}
        return {"state": "complete"}
    l3 = NiosLoad(rest3, plain_log=log.name, repeat=0.02)
    l3.start()
    time.sleep(0.3)
    log.write("{}\n"); log.flush()
    time.sleep(0.6)
    l3.stop(1.0)
    assert sum(1 for p in l3.puts if p["state"] == "running") >= 2, l3.puts
    busy_t = [s["since_start_ms"] for s in res["busy"]]
    assert busy_t == sorted(busy_t) and busy_t[0] < 100
    # F
    data = os.urandom(300000)
    sha = hashlib.sha256(data).hexdigest()
    calls2 = {"n": 0}

    def get_file():
        calls2["n"] += 1
        time.sleep(0.01)
        return data if calls2["n"] != 3 else data[:-1]

    load2 = NiosLoad(rest, plain_log=None, retrigger=0.1, repeat=0.05)
    r2 = series_F(get_file, sha, load2, idle_n=4, busy_s=1.0)
    assert r2["summary"]["idle"]["count"] == 4 and r2["summary"]["idle"]["failures"] == 1
    assert r2["summary"]["busy"]["count"] >= 20 and r2["load"]["puts"] >= 3
    assert all(r["phase"] == "busy" for r in r2["busy"])
    os.unlink(log.name)
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    for name in ("L", "F", "stage"):
        p = sub.add_parser(name)
        p.add_argument("--host", default=tlsb.DEFAULT_HOST)
        p.add_argument("--dry-run", action="store_true")
        if name == "stage":
            continue
        p.add_argument("--build", choices=("nios",), default="nios", help="load generator (the only one in this kit)")
        p.add_argument("--out", required=True)
        p.add_argument("--label", default="")
        p.add_argument("--busy-s", type=float, default=180.0)
        p.add_argument("--idle-n", type=int, default=30 if name == "L" else 10)
        p.add_argument("--interval", type=float, default=0.5)
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--peer-plain-log", help="re-trigger when this peer log grows")
        p.add_argument("--retrigger", type=float, default=2.0)
        p.add_argument("--cfg", help="tlsb_cfg.py --out JSON to embed (what the runner SET)")
    a = ap.parse_args()
    if a.cmd == "selftest":
        selftest()
        return 0
    tlsb.need_host(ap, a.host)
    return {"L": cmd_L, "F": cmd_F, "stage": lambda a: cmd_stage(a) or 0}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
