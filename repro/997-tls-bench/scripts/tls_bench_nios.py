#!/usr/bin/env python3
"""tls_bench_nios.py: Barry's tls_bench_collect.py logic on the harness (series A). Same JSON shape as his nios-results.json.
Drives both Barry's Nios TLS image and the ESP32-offload responder image: both answer PUT/GET /v1/machine:tls_bench.
    python3 -I tls_bench_nios.py run --host <device> --peer <peer ip> --runs 12 --out A-nios.json     |     selftest
(--host / --peer default to the environment variables TLSB_HOST / TLSB_PEER.)
1 warmup + N: PUT /v1/machine:tls_bench, poll GET every 0.25 s until complete (360 s), sleep 2 s, GET /v1/machine:heap.
REST goes through tlsb.rest_call (the kit's one private-harness call)."""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tlsb

FIELDS = ("tcp_ms", "setup_ms", "handshake_ms", "transfer_ms", "plain_tcp_ms", "plain_transfer_ms", "stack_free_words", "idle_heap_free")
OPTIONAL_FIELDS = ("open_total_ms", "stats_rpc_ms")   # the ESP-offload responder only


def collect(rest, info, runs, peer, sleep=time.sleep, clock=time.monotonic, gap=2.0, poll=0.25, wait_peers=None, settle=5.0, art_out=None):
    art = {"firmware": info, "peer": peer, "payload_bytes": 256 * 1024, "warmup": None, "runs": [],
           "conditions": {"tls": "1.2 ECDHE-ECDSA CHACHA20-POLY1305", "authenticated": True,
                          "entropy": "deterministic test fixture; no secrets", "time": "RTC local time converted to UTC",
                          "client": "Nios II/f, -Os -mno-hw-mul, FreeRTOS task priority 1"}}
    if art_out is not None:
        art_out["art"] = art
    for i in range(runs + 1):
        st = rest("PUT", "/v1/machine:tls_bench")
        if st.get("state") != "running":
            art["failure"] = {"run": i, "stage": "PUT", "answer": st}
            break
        if wait_peers:              # matched mode: silent on the device until the peers saw the run, then one GET (2 s retries)
            wait_peers(i)
            sleep(settle)
            poll = 2.0
        end = clock() + 360
        while True:
            out = rest("GET", "/v1/machine:tls_bench")
            if out.get("state") == "complete":
                break
            if clock() >= end:
                art["failure"] = {"run": i, "stage": "timeout", "last": out}
                break
            sleep(poll)
        if art.get("failure"):
            break
        sleep(gap)
        out["idle_heap_free"] = rest("GET", "/v1/machine:heap")["free"]
        for key in ("tls", "entropy", "time", "client"):   # what the build says about itself; Barry's JSON has tls and entropy
            if isinstance(out.get(key), str):
                art["conditions"][key] = out[key]
        if i:
            art["runs"].append(out)
        else:
            art["warmup"] = out
        if not (out["error"] == 0 and out["verify_flags"] == 0 and out["bytes"] == 256 * 1024
                and out["plain_bytes"] == 256 * 1024):
            art["failure"] = {"run": i, "stage": "result", "record": out}
            break
    art["conditions"]["method"] = "peer-log wait, then GET every 2 s" if wait_peers else "GET every 0.25 s until complete (Barry's)"
    art["summary"] = {k: tlsb.summarise([r[k] for r in art["runs"]]) for k in FIELDS}
    for k in OPTIONAL_FIELDS:
        if art["runs"] and all(k in r for r in art["runs"]):
            art["summary"][k] = tlsb.summarise([r[k] for r in art["runs"]])
    return art           # art["failure"] present = the series stopped early; what was collected is still here


def collect_safe(rest, info, runs, wp, peer):
    """collect(), but whatever happens the partial artifact is returned (written by the caller) with `failure` set."""
    holder = {}
    try:
        return collect(rest, info, runs, "%s:18443" % peer, wait_peers=wp, art_out=holder)
    except Exception as exc:  # noqa: BLE001
        art = holder.get("art", {"firmware": info})
        art["failure"] = {"stage": "exception", "error": "%s: %s" % (type(exc).__name__, exc)}
        return art


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cmd", choices=["run", "selftest"])
    ap.add_argument("--host", default=tlsb.DEFAULT_HOST)
    ap.add_argument("--peer", default=tlsb.DEFAULT_PEER, help="address the device connects to; recorded in the JSON")
    ap.add_argument("--runs", type=int, default=12)
    ap.add_argument("--out", default="A-nios.json")
    ap.add_argument("--peer-logs", nargs="*", default=[], help="matched mode: wait on these peer jsonl logs (tls, plain) instead of 0.25 s GET polling")
    ap.add_argument("--cfg", help="tlsb_cfg.py --out JSON to embed")
    a = ap.parse_args()
    if a.cmd == "run":
        tlsb.need_host(ap, a.host)
        if not a.peer:
            ap.error("no peer address: pass --peer or set TLSB_PEER")
    if a.cmd == "selftest":
        n = {"c": 0}
        def rest(m, p):
            if m == "PUT": return {"state": "running"}
            if p.endswith("heap"): return {"free": 5301044}
            n["c"] += 1
            return {"state": "running"} if n["c"] % 3 else {"state": "complete", "error": 0, "verify_flags": 0, "bytes": 262144,
                    "plain_bytes": 262144, "tcp_ms": 5, "setup_ms": 10, "handshake_ms": 35980 + n["c"], "transfer_ms": 7355,
                    "plain_tcp_ms": 5, "plain_transfer_ms": 295, "stack_free_words": 7233}
        art = collect(rest, {"product": "x"}, 3, "p", sleep=lambda s: None)
        seen = []
        art2 = collect(rest, {"product": "x"}, 2, "p", sleep=lambda s: None, wait_peers=seen.append)
        assert seen == [0, 1, 2] and art2["conditions"]["method"].startswith("peer-log")
        assert art["conditions"]["entropy"].startswith("deterministic") and art["conditions"]["time"].startswith("RTC")
        n["c"] = 0
        def rest2(m, p):
            r = rest(m, p)
            if r.get("state") == "complete":
                r.update(tls="ESP32 offload", entropy="hw rng", time="SNTP UTC", open_total_ms=40, stats_rpc_ms=7)
            return r
        a3 = collect(rest2, {"product": "x"}, 2, "p", sleep=lambda s: None)
        assert a3["conditions"]["tls"] == "ESP32 offload" and a3["conditions"]["time"] == "SNTP UTC"
        assert a3["summary"]["stats_rpc_ms"]["median"] == 7
        assert len(art["runs"]) == 3 and art["warmup"] and art["summary"]["transfer_ms"]["median"] == 7355
        bad = collect(lambda m, p: {"state": "busy"}, {"p": 1}, 2, "p", sleep=lambda s: None)
        assert bad["failure"]["stage"] == "PUT" and bad["runs"] == []
        print("selftest ok"); return 0
    def body():
        c = tlsb.client(a.host)
        info = c.get_info()
        def rest(m, p): return tlsb.rest_call(c, m, p)
        wp = None
        if a.peer_logs:
            T = tlsb
            base = {p: T.count_lines(p) for p in a.peer_logs}
            def wp(i):
                dl = time.monotonic() + 400
                while time.monotonic() < dl:
                    if all(T.count_lines(p) - base[p] >= i + 1 for p in a.peer_logs):
                        return
                    time.sleep(1.0)
                raise TimeoutError("peers never logged run %d" % i)
        art = collect_safe(rest, info, a.runs, wp, a.peer)
        art["config_readback"] = tlsb.config_readback(c)
        if a.cfg:
            art["config_set_record"] = json.load(open(a.cfg))
        json.dump(art, open(a.out, "w"), indent=2)
        print(json.dumps(art.get("summary"), indent=2))
        if art.get("failure"):
            print("SERIES STOPPED EARLY: %s" % json.dumps(art["failure"])[:300], file=sys.stderr)
            sys.exit(5)
    tlsb.locked(a.host, body)

if __name__ == "__main__":
    sys.exit(main())
