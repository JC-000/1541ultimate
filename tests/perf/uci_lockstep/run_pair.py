#!/usr/bin/env python3
"""Two Ultimates in one lockstep session through a relay on this machine; report what it cost.

    tests/perf/uci_lockstep/run_pair.py --host-a <ultimate-a> --host-b <ultimate-b> \\
        [--seconds 180] [--delay 2] [--wan-delay-ms 17.5 --wan-jitter-ms 2.5 --wan-loss 0.01]
    tests/perf/uci_lockstep/run_pair.py --host-a <ultimate-a> --host-b <ultimate-b> --matrix

Device A HOSTs at start; the relay gives every HOST the room code --code; device B JOINs that
code once A is waiting. Both run client/lockstep.prg, started over REST (runners:run_prg) with
its CONFIG block patched first. The relay (relay/, started here) can put a simulated WAN on each
C64's leg: --wan-* apply per leg and per direction, so the one-way delay between the two C64s
is twice --wan-delay-ms.

Every second it reads both STATUS blocks (machine:readmem); at the end it reads each device's
READ histogram, stops both programs with 'Q' (the client says BYE and closes its socket), and
prints per device: ticks, stalls a minute, empty READs, late/lost replies, UCI errors, the worst
frame in CPU cycles, and the relay's digest comparisons. --matrix runs the six paths of the
README one after the other and prints them as one table.

Needs only Python 3 and a network route to both devices. U64_PASS (or --password) carries the
devices' REST password, if they have one.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRG = HERE / "client" / "lockstep.prg"
LABELS = HERE / "client" / "build" / "lockstep.labels"

CONFIG_ADDR = 0x0810
CONFIG_SIZE = 32
CMD_ADDR = CONFIG_ADDR + 24          # write b"Q": hang up, close the socket, stop
STATUS_ADDR = 0x0830
STATUS_SIZE = 64
MODE_STOPPED = 0xFF
# READ histogram (client/uci.s uci_hist_lo / uci_hist_hi): 16 data + 16 empty buckets of how
# many polls each READ kept the interface busy. Taken from client/build/lockstep.labels when
# that exists (after `make`), else these, which match the committed lockstep.prg.
HIST_LO, HIST_HI, HIST_N = 0x1DE3, 0x1E03, 16
FRAME_BUDGET = 17_095                # CPU cycles in one NTSC frame
FLAG_HOST, FLAG_JOIN = 0x01, 0x02
UCI_STORE, UCI_ITEM = "C64 and Cartridge Settings", "Command Interface"
U64_STORE = "U64 Specific Settings"

PATHS = {
    "lan": dict(desc="LAN", delay=2, wan=0.0, jit=0.0, loss=0.0),
    "lan-loss": dict(desc="LAN, 1% loss", delay=2, wan=0.0, jit=0.0, loss=0.01),
    "wan5": dict(desc="17.5 ms +-2.5 each leg", delay=5, wan=17.5, jit=2.5, loss=0.0),
    "wan5-loss": dict(desc="17.5 ms +-2.5 each leg, 1% loss", delay=5, wan=17.5, jit=2.5, loss=0.01),
    "wan10": dict(desc="17.5 ms +-5 each leg", delay=5, wan=17.5, jit=5.0, loss=0.0),
    "wan10-loss": dict(desc="17.5 ms +-5 each leg, 1% loss", delay=5, wan=17.5, jit=5.0, loss=0.01),
}


# ---- the device, over REST ------------------------------------------------------------------
class Device:
    def __init__(self, host: str, password: str) -> None:
        self.host = host
        self.password = password

    def request(self, method: str, path: str, params: dict | None = None,
                body: bytes | None = None, ctype: str = "", timeout: float = 10.0) -> bytes:
        url = f"http://{self.host}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, data=body, method=method)
        if self.password:
            req.add_header("X-Password", self.password)
        if ctype:
            req.add_header("Content-Type", ctype)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()

    def info(self) -> dict:
        return json.loads(self.request("GET", "/v1/info"))

    def config(self, store: str, item: str) -> str | None:
        path = f"/v1/configs/{urllib.parse.quote(store, safe='')}/{urllib.parse.quote(item, safe='')}"
        try:
            entry = json.loads(self.request("GET", path)).get(store, {}).get(item)
        except (urllib.error.HTTPError, ValueError):
            return None
        if isinstance(entry, dict):
            entry = entry.get("current")
        return None if entry is None else str(entry)

    def set_config(self, store: str, item: str, value: str) -> None:
        path = f"/v1/configs/{urllib.parse.quote(store, safe='')}/{urllib.parse.quote(item, safe='')}"
        self.request("PUT", path, {"value": value})

    def run_prg(self, prg: bytes) -> None:
        self.request("POST", "/v1/runners:run_prg", body=prg,
                     ctype="application/octet-stream", timeout=20.0)

    def read(self, addr: int, n: int) -> bytes:
        return self.request("GET", "/v1/machine:readmem", {"address": f"{addr:04X}", "length": n})

    def write(self, addr: int, data: bytes) -> None:
        self.request("PUT", "/v1/machine:writemem", {"address": f"{addr:04X}", "data": data.hex()})


# ---- the client's CONFIG and STATUS blocks (client/main.s) -----------------------------------
def config_block(relay_ip: str, port: int, *, host: bool = False, join: str = "") -> bytes:
    flags = (FLAG_HOST if host else 0) | (FLAG_JOIN if join else 0)
    code = join.upper().encode("ascii").ljust(4, b"\0")[:4]
    blk = (b"NCFG" + bytes([1]) + socket.inet_aton(relay_ip) + struct.pack("<H", port)
           + bytes([flags]) + code)
    return blk.ljust(CONFIG_SIZE, b"\0")


def patch_prg(prg: bytes, addr: int, block: bytes) -> bytes:
    load = prg[0] | (prg[1] << 8)
    off = addr - load + 2
    if not 2 <= off <= len(prg) - len(block):
        raise ValueError(f"${addr:04X} is outside the PRG (loads at ${load:04X})")
    return prg[:off] + block + prg[off + len(block):]


@dataclass
class Status:
    mode: int           # 0 off, 1 lobby, 2 session, $FF stopped
    lobby: int          # lobby status (1 = waiting in a room)
    delay: int          # input delay in ticks
    end: int            # why the last session ended (0 = it has not)
    ticks: int          # session ticks run (16 bit)
    stalls: int         # frames that waited for the other C64's input (16 bit)
    rtt: int            # LOBBY round trip, frames
    net_status: int
    net_err: int
    writes: int
    reads: int
    empty: int          # READs that came back with no datagram
    errors: int         # UCI / network errors
    rx: int
    code: str
    net_max: int        # worst frame of the network layer, CPU cycles
    work_max: int       # worst whole frame, CPU cycles
    late_replies: int   # replies taken a frame later than the newest one sent (8 bit)
    lost_replies: int   # replies never received (8 bit)
    late_writes: int    # frames whose datagram left in a later frame
    skips: int          # frames that sent nothing to drain a reply backlog


def parse_status(raw: bytes) -> Status | None:
    if len(raw) < STATUS_SIZE or raw[:4] != b"NSTA" or raw[4] != 1:
        return None
    w = lambda o: raw[o] | (raw[o + 1] << 8)  # noqa: E731
    return Status(mode=raw[6], lobby=raw[8], delay=raw[10], end=raw[11], ticks=w(14),
                  stalls=w(16), rtt=raw[21], net_status=raw[22], net_err=raw[23], writes=w(24),
                  reads=w(26), empty=w(28), errors=w(30), rx=w(34),
                  code=raw[36:40].replace(b"\0", b"").decode("ascii", "replace"),
                  net_max=w(44), work_max=w(48), late_replies=raw[57], lost_replies=raw[58],
                  late_writes=w(60), skips=w(62))


def hist_addrs() -> tuple[int, int]:
    if LABELS.exists():
        found = {}
        for line in LABELS.read_text().splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] in (".uci_hist_lo", ".uci_hist_hi"):
                found[parts[2]] = int(parts[1], 16)
        if len(found) == 2:
            return found[".uci_hist_lo"], found[".uci_hist_hi"]
    return HIST_LO, HIST_HI


def read_hist(dev: Device) -> dict:
    lo_a, hi_a = hist_addrs()
    lo, hi = dev.read(lo_a, 2 * HIST_N), dev.read(hi_a, 2 * HIST_N)
    v = [lo[i] | (hi[i] << 8) for i in range(2 * HIST_N)]
    return {"data": v[:HIST_N], "empty": v[HIST_N:]}


def lan_ip_towards(host: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def wait_status(dev: Device, cond, timeout: float, every: float = 0.5) -> Status | None:
    end = time.monotonic() + timeout
    while True:
        st = parse_status(dev.read(STATUS_ADDR, STATUS_SIZE))
        if st is not None and cond(st):
            return st
        if time.monotonic() >= end:
            return None
        time.sleep(every)


# ---- one run ---------------------------------------------------------------------------------
def check_device(name: str, dev: Device, enable_uci: bool) -> dict:
    info = dev.info()
    ident = {k: info.get(k) for k in ("product", "firmware_version", "git_commit_hash")}
    uci = dev.config(UCI_STORE, UCI_ITEM)
    if uci != "Enabled":
        if not enable_uci:
            raise SystemExit(f"{name} {dev.host}: {UCI_ITEM} is {uci!r}; enable it in "
                             f"{UCI_STORE}, or pass --enable-uci")
        dev.set_config(UCI_STORE, UCI_ITEM, "Enabled")
    for item in ("System Mode", "Turbo Control", "CPU Speed"):
        value = dev.config(U64_STORE, item)
        if value is not None:
            ident[item] = value.strip()
    print(f"  {name} {dev.host}: {ident}")
    if ident.get("Turbo Control", "Off") != "Off":
        print(f"  WARNING {name}: Turbo Control is not Off; the client is timed for 1 MHz")
    return ident


def run_one(args, devs: dict[str, Device], path: dict, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    relay_ip = args.relay_ip or lan_ip_towards(args.host_a)
    prg = PRG.read_bytes()
    prgs = {"A": patch_prg(prg, CONFIG_ADDR, config_block(relay_ip, args.port, host=True)),
            "B": patch_prg(prg, CONFIG_ADDR, config_block(relay_ip, args.port, join=args.code))}
    summary_path = out / "relay.json"
    summary_path.unlink(missing_ok=True)
    cmd = [sys.executable, "-m", "relay", "--bind", relay_ip, "--port", str(args.port),
           "--host-code", args.code, "--delay", str(path["delay"]), "--summary",
           str(summary_path), "--log-level", "debug",
           "--wan-delay-ms", str(path["wan"]), "--wan-jitter-ms", str(path["jit"]),
           "--wan-loss", str(path["loss"]), "--wan-seed", str(args.wan_seed)]
    print(f"=== {path['desc']}: delay {path['delay']}, relay {relay_ip}:{args.port}, "
          f"{args.seconds:g} s ===")
    with open(out / "relay.log", "w") as relay_log:
        relay = subprocess.Popen(cmd, cwd=HERE, stdout=relay_log, stderr=subprocess.STDOUT)
        final: dict[str, Status] = {}
        hist: dict[str, dict] = {}
        history = []
        note = ""
        try:
            time.sleep(1.0)
            if relay.poll() is not None:
                raise SystemExit(f"the relay did not start: see {out / 'relay.log'}")
            devs["A"].run_prg(prgs["A"])
            a = wait_status(devs["A"], lambda s: s.lobby == 1 and s.code == args.code, 30.0)
            if a is None:
                note = "A never waited in its room"
            else:
                devs["B"].run_prg(prgs["B"])
                ok = all(wait_status(d, lambda s: s.mode == 2, 30.0) is not None
                         for d in devs.values())
                if not ok:
                    note = "the session did not start on both"
                else:
                    t_end = time.monotonic() + args.seconds
                    while time.monotonic() < t_end:
                        time.sleep(1.0)
                        row = {k: parse_status(d.read(STATUS_ADDR, STATUS_SIZE))
                               for k, d in devs.items()}
                        history.append({k: asdict(v) if v else None for k, v in row.items()})
                        if any(v is None or v.mode != 2 for v in row.values()):
                            note = "a C64 left the session early"
                            break
                        if not args.quiet:
                            print("    " + " | ".join(
                                f"{k} ticks {s.ticks:5d} stalls {s.stalls:4d} empty {s.empty:5d}"
                                f" err {s.errors} max {s.work_max}" for k, s in row.items()))
                    for k, d in devs.items():
                        final[k] = parse_status(d.read(STATUS_ADDR, STATUS_SIZE))
                        hist[k] = read_hist(d)
        finally:
            for d in devs.values():     # leave no socket open: the firmware has few UDP PCBs
                try:
                    d.write(CMD_ADDR, b"Q")
                except (OSError, urllib.error.URLError):
                    pass
            for d in devs.values():
                try:
                    wait_status(d, lambda s: s.mode == MODE_STOPPED, 5.0, 0.25)
                except (OSError, urllib.error.URLError):
                    pass
            if relay.poll() is None:
                relay.send_signal(signal.SIGINT)
                try:
                    relay.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    relay.kill()
    relay_sum = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    sess = relay_sum.get("hub_sessions", [{}])[-1] if relay_sum.get("hub_sessions") else {}
    result = {"path": path, "seconds": args.seconds, "note": note,
              "final": {k: asdict(v) for k, v in final.items() if v},
              "hist": hist, "digest_ok": sess.get("digest_ok"), "digest_bad": sess.get("digest_bad"),
              "relay": relay_sum, "history": history}
    (out / "result.json").write_text(json.dumps(result, indent=1))
    print_result(result)
    return result


def per_min(n: int, seconds: float) -> float:
    return n / seconds * 60


def empty_hold(h: dict) -> str:
    n = sum(h["empty"])
    return f"{sum(k * c for k, c in enumerate(h['empty'])) / n:.1f}" if n else "-"


def print_result(r: dict) -> None:
    if r["note"]:
        print(f"  NOT MEASURED: {r['note']}")
    for k, s in r["final"].items():
        s = Status(**s)
        rate = s.ticks / r["seconds"]
        print(f"  {k}: {s.ticks} ticks ({rate:.1f}/s), stalls {per_min(s.stalls, r['seconds']):.1f}"
              f"/min, delay {s.delay}, LOBBY RTT {s.rtt} frames; UCI {s.writes} writes, "
              f"{s.reads} reads, {s.empty} empty (held {empty_hold(r['hist'][k])} polls on "
              f"average); replies late/lost {s.late_replies}/{s.lost_replies}; skips {s.skips}; "
              f"errors {s.errors}; worst frame {s.work_max} of {FRAME_BUDGET} cycles")
    print(f"  relay digests: {r['digest_ok']} equal, {r['digest_bad']} different")


def table(results: list[dict]) -> str:
    lines = ["| Path | Stalls/min A / B | Ticks/s A / B | Empty READs A / B | Late/lost A / B "
             "| Errors | Worst frame (cycles) | Digests equal/different |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        f = r["final"]
        if len(f) < 2:
            lines.append(f"| {r['path']['desc']} | not measured: {r['note']} |||||||")
            continue
        a, b = Status(**f["A"]), Status(**f["B"])
        sec = r["seconds"]
        lines.append(
            f"| {r['path']['desc']} | {per_min(a.stalls, sec):.1f} / {per_min(b.stalls, sec):.1f} "
            f"| {a.ticks / sec:.1f} / {b.ticks / sec:.1f} | {a.empty} / {b.empty} "
            f"| {a.late_replies}/{a.lost_replies} / {b.late_replies}/{b.lost_replies} "
            f"| {a.errors + b.errors} | {max(a.work_max, b.work_max)} "
            f"| {r['digest_ok']}/{r['digest_bad']} |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host-a", required=True, help="the Ultimate that HOSTs")
    ap.add_argument("--host-b", required=True, help="the Ultimate that JOINs")
    ap.add_argument("--password", default=os.environ.get("U64_PASS", ""),
                    help="REST password of both devices (default: $U64_PASS)")
    ap.add_argument("--relay-ip", default="", help="this machine's address as the devices see it "
                    "(default: the one that routes to --host-a)")
    ap.add_argument("--port", type=int, default=6520)
    ap.add_argument("--code", default="TEST", help="room code (A-Z without I and O, 2-9)")
    ap.add_argument("--seconds", type=float, default=180.0)
    ap.add_argument("--delay", type=int, default=2, help="input delay in ticks (one run)")
    ap.add_argument("--wan-delay-ms", type=float, default=0.0, help="per leg, each way")
    ap.add_argument("--wan-jitter-ms", type=float, default=0.0)
    ap.add_argument("--wan-loss", type=float, default=0.0)
    ap.add_argument("--wan-seed", type=int, default=1)
    ap.add_argument("--matrix", action="store_true", help="run the six paths of the README")
    ap.add_argument("--only", default="", help=f"with --matrix: some of {', '.join(PATHS)}")
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("--label", default="", help="subdirectory of --out (e.g. the firmware build)")
    ap.add_argument("--enable-uci", action="store_true",
                    help=f"set {UCI_ITEM} to Enabled if it is not")
    ap.add_argument("--quiet", action="store_true", help="no per-second lines")
    args = ap.parse_args()

    devs = {"A": Device(args.host_a, args.password), "B": Device(args.host_b, args.password)}
    ident = {k: check_device(k, d, args.enable_uci) for k, d in devs.items()}
    out = Path(args.out) / (args.label or time.strftime("%Y%m%d-%H%M%S"))
    if args.matrix:
        names = args.only.split(",") if args.only else list(PATHS)
        runs = [(n, PATHS[n]) for n in names]
    else:
        runs = [("custom", dict(desc=f"{args.wan_delay_ms:g} ms +-{args.wan_jitter_ms:g} each "
                                f"leg, {args.wan_loss:.1%} loss", delay=args.delay,
                                wan=args.wan_delay_ms, jit=args.wan_jitter_ms,
                                loss=args.wan_loss))]
    results = [run_one(args, devs, path, out / name) for name, path in runs]
    md = (f"Devices: A {args.host_a} {ident['A']}, B {args.host_b} {ident['B']}; "
          f"{args.seconds:g} s per path.\n\n" + table(results) + "\n")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(md)
    print("\n" + md + f"\nResults in {out}")
    return 0 if all(len(r["final"]) == 2 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
