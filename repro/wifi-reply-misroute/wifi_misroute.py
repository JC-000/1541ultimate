#!/usr/bin/env python3
"""Repro 1: a WiFi command reply delivered to the wrong waiter (deepdive-q7).

Hypothesis: outgoing WiFi frames register in tasksWaitingForReply by TX buffer
number (BUFARGS in wifi_cmd.h, via wifi_tx_packet), and the TX buffer returns to
the pool when the UART has sent it, before the reply arrives. A reply to a
command (here CMD_WIFI_AUTOCONNECT, sent from the UI task by the F2 settings page
item "Connect to last AP") can then notify a frame-sending task instead, and the
UI task waits in xTaskNotifyWait(portMAX_DELAY) for ever.

Detection: after every press of Enter on "Connect to last AP" the page is
redrawn when the UI task comes back (CFG_TYPE_FUNC sets refresh=true before the
call). If no byte arrives, the script moves the cursor DOWN to force a redraw. A
UI task that is still blocked answers neither. Meanwhile REST /v1/info over
Ethernet is polled: it must still answer for the result to count as the
misroute signature rather than a dead device.

Modes (exactly one):
  --preflight   READ-ONLY. REST, ping-free, one passive telnet screen read, FTP LIST of the load file.
  --selftest    no device: menu-navigation and stall logic against a stub backend.
  --control     device-changing (device lock, telnet session, "Connect to last AP" x N), NO FTP load.
  --load        the same with the FTP RETR load over the WiFi address running.
Run from the root of a 1541ultimate checkout (it uses tests/lib and tests/e2e/lib),
or set ULTIMATE_REPO to one. The load must really travel over WiFi: if the Ethernet
port is in the same subnet as the WiFi address, lwIP may answer the FTP load via
Ethernet and the repro proves nothing. Check that replies from --wifi carry the WiFi
MAC (e.g. tcpdump -e on the host) before trusting a NO HIT.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = Path(os.environ.get("ULTIMATE_REPO", ".")).resolve()
sys.path.insert(0, str(REPO / "tests" / "e2e" / "lib"))
sys.path.insert(0, str(REPO / "tests" / "lib"))
sys.path.insert(0, str(HERE))
import bootstrap  # noqa: F401

LOGDIR = HERE / "logs"
ETH = None    # --eth: the Ultimate's Ethernet address (REST, telnet)
WIFI = None   # --wifi: its WiFi address (FTP load)
CATEGORY = "WiFi settings"          # note the lower-case s: that is the store's name
TARGET_ITEM = "Connect to last AP"
FORBIDDEN = ("Forget APs", "Disconnect", "Enter AP manually", "Select AP from list")
ENTRY_ROWS = range(2, 23)           # telnet_backend.TELNET_ENTRY_ROWS


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


class Log:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)

    def __call__(self, msg):
        line = f"{ts()} {msg}"
        print(line, flush=True)
        self.f.write(line + "\n")


def rest_get(host, path, timeout=3.0):
    t0 = time.monotonic()
    with urllib.request.urlopen(f"http://{host}{path}", timeout=timeout) as r:
        body = r.read()
    return json.loads(body), time.monotonic() - t0


# ---------------------------------------------------------------- menu driving

def current(tb):
    """Text of the highlighted row of the innermost framed list (F2 opens a framed box over the root)."""
    frames = tb.framed_selections()
    if not frames:
        raise RuntimeError("no framed list on screen")
    return list(frames.values())[-1][1].strip()


def goto(tb, label, limit=40, exact_prefix=True):
    """Move the cursor DOWN (wrapping not assumed) until the selected row starts with `label`.

    `tb` needs send_key(name) and selected_text(entry_rows). Raises RuntimeError with the
    screen if the label is not found; never presses Enter.
    """
    seen = []
    for _ in range(limit):
        text = current(tb)
        if text.startswith(label) if exact_prefix else label in text:
            return text
        if text in seen:
            break
        seen.append(text)
        tb.send_key("DOWN")
    raise RuntimeError(f"{label!r} not reached; rows visited: {seen}")


def open_target_page(tb, log):
    tb.send_key("F2")
    log("F2 pressed (settings browser)")
    log("selected: " + goto(tb, CATEGORY))
    tb.send_key("ENTER")
    log("entered " + CATEGORY)
    sel = goto(tb, TARGET_ITEM)
    assert not any(sel.startswith(f) for f in FORBIDDEN), sel
    log(f"cursor on: {sel!r}")


def redraw_bytes(tb, timeout):
    """Bytes drawn by the device within `timeout`s of the last send (0 = nothing)."""
    import select
    end = time.monotonic() + timeout
    total = 0
    tb.first_byte_at = None
    while time.monotonic() < end:
        ready, _, _ = select.select([tb.sock], [], [], 0.1)
        if ready:
            chunk = tb.sock.recv(65536)
            if not chunk:
                return -1                      # the device closed the session
            tb.screen.feed(chunk)
            if tb.first_byte_at is None:
                tb.first_byte_at = time.monotonic()
            total += len(chunk)
            end = min(end, time.monotonic() + 0.4)   # redraw under way: let it finish
    return total


def press_and_probe(tb, stall_s, enter_wait=3.0):
    """Enter on the target, then prove the UI task is back.

    Returns (alive, notes, latency, stalled): latency is enter -> first redraw byte in
    seconds (None when nothing came); stalled means Enter alone drew nothing within enter_wait.
    """
    t0 = time.monotonic()
    tb._send(b"\r", "ENTER")                  # the single device-affecting key
    n = redraw_bytes(tb, enter_wait)
    lat = (tb.first_byte_at - t0) if tb.first_byte_at else None
    notes = [f"enter->{n}B"]
    if n > 0:
        return True, notes, lat, False
    tb._send(b"\x1b[B", "DOWN")               # probe: moves cursor to the next row
    n = redraw_bytes(tb, stall_s)
    notes.append(f"probe-down->{n}B")
    if n <= 0:
        return False, notes, None, True
    lat = tb.first_byte_at - t0
    tb._send(b"\x1b[A", "UP")                 # back on the target row
    redraw_bytes(tb, 3.0)
    return True, notes, lat, True


# ---------------------------------------------------------------------- runs

def preflight(log):
    info, rtt = rest_get(ETH, "/v1/info")
    log(f"REST {ETH}/v1/info {rtt * 1000:.0f} ms: {info['product']} fw {info['firmware_version']} "
        f"{info['git_commit_hash']} core {info['core_version']} wifi_mac {info['wifi_mac']}")
    wi, rtt = rest_get(WIFI, "/v1/info")
    log(f"REST {WIFI}/v1/info {rtt * 1000:.0f} ms (via WiFi address): same unique_id? "
        f"{wi['unique_id'] == info['unique_id']}")
    cfg, _ = rest_get(ETH, "/v1/configs/WiFi%20settings")
    log("WiFi settings: " + json.dumps(cfg[CATEGORY]))
    from telnet_backend import TelnetBackend
    tb = TelnetBackend(ETH, 23, None, 5.0)
    rows = [r.rstrip() for r in tb.screen.rows() if r.strip()]
    tb.close()
    wifi_row = [r for r in rows if r.startswith("WiFi")]
    log(f"telnet root screen WiFi row: {wifi_row}")
    ok = bool(wifi_row) and "Link Up" in wifi_row[0] and WIFI in wifi_row[0]
    log("PREFLIGHT " + ("OK: WiFi associated at " + WIFI if ok else "NOT READY: WiFi row not Link Up"))
    return 0 if ok else 2


def run(args, with_load):
    try:
        from c64_test_harness.backends.device_lock import DeviceLock
    except ImportError:
        def DeviceLock(_host):
            return nullcontext()
    import ftp_load
    from telnet_backend import TelnetBackend
    LOGDIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    log = Log(LOGDIR / f"r1-{'load' if with_load else 'control'}-{stamp}.log")
    verdict = 0
    with DeviceLock(ETH):
        info, _ = rest_get(ETH, "/v1/info")
        before, _ = rest_get(ETH, "/v1/configs/WiFi%20settings")
        log(f"device {info['product']} git_commit_hash={info['git_commit_hash']} fw {info['firmware_version']} "
            f"core {info['core_version']} fpga {info['fpga_version']}")
        log("full /v1/info (REST has no ESP32 module IDENT field; the build's IDENT_MINOR is what identifies the module): "
            + json.dumps(info))
        log(f"mode {'GREEN (any stall-then-recovery is a FAIL)' if args.green else 'RED (permanent freeze = HIT)'} "
            f"stall={args.stall}s n={args.n}")
        log("settings recorded (read only, nothing written; WiFi Enabled must already be Enabled): "
            + json.dumps(before[CATEGORY]))
        if before[CATEGORY].get("WiFi Enabled") != "Enabled":
            log("ABORT: WiFi Enabled is not Enabled; enable WiFi on the device first")
            return 2
        stop = threads = stats = None
        tb = TelnetBackend(ETH, 23, None, 5.0)
        try:
            if with_load:
                stop, threads, stats = ftp_load.start_load(WIFI, 21, args.path, args.streams, log=log)
                log(f"load started: {args.streams} stream(s) RETR {args.path} from {WIFI}; ramp {args.ramp}s")
                time.sleep(args.ramp)
            open_target_page(tb, log)
            lats, stalls = [], 0
            for i in range(1, args.n + 1):

                alive, notes, lat, stalled = press_and_probe(tb, args.stall, args.stall if args.green else 3.0)
                if alive:
                    if lat is not None:
                        lats.append(lat)
                    tag = ""
                    if args.green and stalled:
                        stalls += 1
                        tag = " STALL-THEN-RECOVERY (FAIL in GREEN)"
                    log(f"#{i:02d} UI alive {notes} latency={lat if lat is None else round(lat, 3)}s{tag}")
                    time.sleep(args.gap)
                    continue
                # Candidate hit. Keep checking REST (Ethernet) and the telnet session for the confirm window.
                log(f"#{i:02d} NO REDRAW for {args.stall}s {notes}; confirming for {args.confirm}s")
                end = time.monotonic() + args.confirm
                rest_ok = 0
                recovered = False
                while time.monotonic() < end:
                    try:
                        _, rtt = rest_get(ETH, "/v1/info", timeout=3.0)
                        rest_ok += 1
                    except Exception as exc:
                        log(f"   REST over Ethernet failed: {exc}")
                    if redraw_bytes(tb, 2.0) > 0:
                        recovered = True
                        break
                if recovered:
                    stalls += 1
                    log(f"#{i:02d} UI came back after a stall: slow, not hung"
                        + (" -> FAIL in GREEN (bounded timeout, not a fix)" if args.green else " (not the RED signature)"))
                    continue
                log(f"#{i:02d} HIT: telnet UI silent {args.stall + args.confirm}s while REST answered {rest_ok} times")
                log("SCREEN AT HIT:\n" + "\n".join(r.rstrip() for r in tb.screen.rows() if r.strip()))
                verdict = 1
                break
            else:
                log(f"NO HIT in {args.n} presses ({'with' if with_load else 'without'} load)")
            if lats:
                srt = sorted(lats)
                log(f"LATENCY enter->redraw over {len(lats)} presses: max {srt[-1]:.3f}s median {srt[len(srt) // 2]:.3f}s")
            if args.green:
                log(f"GREEN {'FAIL' if (stalls or verdict) else 'PASS'}: stalls={stalls} permanent_freeze={bool(verdict)}")
                if stalls:
                    verdict = 1
            if with_load and stats:
                log(f"load totals: {stats.bytes} B, files {stats.files}, errors {stats.errors} {stats.last_error}")
        finally:
            if stop:
                stop.set()
            if verdict == 0:                   # only leave the page when the UI is alive
                try:                           # ESC leaves the page, ESC again asks "Save changes to Flash?"
                    tb._send(b"\x1b", "ESC")
                    redraw_bytes(tb, 2.0)
                    tb._send(b"\x1b", "ESC")
                    redraw_bytes(tb, 2.0)
                    if any("Save changes" in r for r in tb.screen.rows()):
                        tb._send(b"n", "No")
                        redraw_bytes(tb, 2.0)
                except OSError:
                    pass
            tb.close()
    return verdict


def selftest():
    class Stub:
        def __init__(self, rows):
            self.rows, self.i, self.keys = rows, 0, []

        def framed_selections(self):
            return {(0, 0, 0, 0): (self.i, self.rows[self.i], self.rows)}

        def send_key(self, k):
            self.keys.append(k)
            if k == "DOWN":
                self.i = min(self.i + 1, len(self.rows) - 1)

    s = Stub(["Audio Mixer", "Printer Settings", "WiFi settings", "Tape"])
    assert goto(s, CATEGORY) == "WiFi settings" and s.keys == ["DOWN", "DOWN"]
    s = Stub(["WiFi Enabled  Enabled", "Disconnect", "Connect to last AP", "Select AP from list"])
    assert goto(s, TARGET_ITEM) == "Connect to last AP"
    assert "ENTER" not in s.keys, "goto must never press Enter"
    try:
        goto(Stub(["a", "b"]), "nope")
        raise SystemExit("goto should have failed")
    except RuntimeError as exc:
        assert "not reached" in str(exc)
    # press_and_probe against a socket pair: silent peer = stall, chatty peer = alive
    import socket

    class TB:
        pass
    a, b = socket.socketpair()
    tb = TB()
    tb.sock = a
    tb.sent = []
    tb._send = lambda payload, what: tb.sent.append(payload)

    class Scr:
        def feed(self, d):
            pass
    tb.screen = Scr()
    tb.first_byte_at = None
    alive, notes, lat, stalled = press_and_probe(tb, 1.0, 1.0)
    assert not alive and stalled and lat is None and tb.sent == [b"\r", b"\x1b[B"], (alive, notes, tb.sent)
    b.send(b"redraw")
    tb.sent.clear()
    alive, notes, lat, stalled = press_and_probe(tb, 1.0, 1.0)
    assert alive and not stalled and lat is not None and lat < 0.5 and tb.sent == [b"\r"], (alive, notes, lat)
    # delayed reply: silent past enter_wait, then the probe is answered -> stall-then-recovery
    import threading
    tb.sent.clear()
    threading.Timer(1.5, lambda: b.send(b"late")).start()
    alive, notes, lat, stalled = press_and_probe(tb, 2.0, 1.0)
    assert alive and stalled and lat >= 1.0, (alive, notes, lat, stalled)
    print("selftest OK: navigation never presses Enter; silent peer -> stall; chatty peer -> alive")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--preflight", action="store_true")
    g.add_argument("--selftest", action="store_true")
    g.add_argument("--control", action="store_true")
    g.add_argument("--load", action="store_true")
    ap.add_argument("-n", type=int, default=20, help="presses of Connect to last AP")
    ap.add_argument("--gap", type=float, default=2.0, help="seconds between presses")
    ap.add_argument("--green", action="store_true", help="GREEN check: stall limit 3s, any stall-then-recovery fails")
    ap.add_argument("--stall", type=float, default=None, help="seconds of silence before a press is a candidate hit")
    ap.add_argument("--confirm", type=float, default=50.0, help="further seconds a candidate must stay silent")
    ap.add_argument("--streams", type=int, default=2)
    ap.add_argument("--ramp", type=float, default=8.0)
    ap.add_argument("--path", help="a file of a few MB on the device, fetched over FTP (e.g. /USB1/big.bin)")
    ap.add_argument("--eth", help="the Ultimate's Ethernet IP address")
    ap.add_argument("--wifi", help="the Ultimate's WiFi IP address")
    a = ap.parse_args()
    global ETH, WIFI
    ETH, WIFI = a.eth, a.wifi
    if not a.selftest and not (ETH and WIFI):
        ap.error("--eth and --wifi are required")
    if a.load and not a.path:
        ap.error("--load needs --path")
    if a.stall is None:
        a.stall = 3.0 if a.green else 10.0
    if a.green and a.stall > 3.0:
        ap.error("--green needs --stall <= 3")
    if a.selftest:
        return selftest()
    if a.preflight:
        LOGDIR.mkdir(exist_ok=True)
        return preflight(Log(LOGDIR / f"r1-preflight-{time.strftime('%Y%m%dT%H%M%S')}.log"))
    return run(a, with_load=a.load)


if __name__ == "__main__":
    sys.exit(main())
