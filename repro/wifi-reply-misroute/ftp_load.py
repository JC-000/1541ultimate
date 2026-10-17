#!/usr/bin/env python3
"""Loop RETR of one file over FTP (anonymous) and log throughput and errors.

Used as the load for repro 1: the device must send full-size frames over its WiFi
netif, so point --host at the device's WiFi address, not the Ethernet one.

Library use: start_load(...) returns (stop_event, threads, stats); CLI use below.
"""
import argparse
import ftplib
import sys
import threading
import time
from datetime import datetime

BLOCK = 32768


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = 0
        self.files = 0
        self.errors = 0
        self.last_error = ""

    def add(self, n):
        with self.lock:
            self.bytes += n

    def done(self):
        with self.lock:
            self.files += 1

    def error(self, msg):
        with self.lock:
            self.errors += 1
            self.last_error = msg


def stream(idx, host, port, path, stats, stop, log, timeout):
    while not stop.is_set():
        ftp = ftplib.FTP()
        t0 = time.monotonic()
        got = 0
        try:
            ftp.connect(host, port, timeout=timeout)
            ftp.login("anonymous", "repro@example.invalid")
            ftp.voidcmd("TYPE I")

            def cb(b):
                nonlocal got
                got += len(b)
                stats.add(len(b))
                if stop.is_set():
                    raise InterruptedError("stop")
            ftp.retrbinary(f"RETR {path}", cb, blocksize=BLOCK)
            dt = time.monotonic() - t0
            stats.done()
            log(f"[s{idx}] RETR ok {got} B in {dt:.2f}s = {got / dt / 1e6:.3f} MB/s")
            try:
                ftp.quit()
            except Exception:
                pass
        except InterruptedError:
            break
        except Exception as exc:
            dt = time.monotonic() - t0
            stats.error(f"{type(exc).__name__}: {exc}")
            log(f"[s{idx}] ERROR after {got} B / {dt:.2f}s: {type(exc).__name__}: {exc}")
            try:
                ftp.close()
            except Exception:
                pass
            stop.wait(1.0)


def reporter(stats, stop, log, interval=2.0):
    last_b, last_t = 0, time.monotonic()
    while not stop.wait(interval):
        now = time.monotonic()
        with stats.lock:
            b, f, e = stats.bytes, stats.files, stats.errors
        log(f"[sum] {(b - last_b) / (now - last_t) / 1e6:.3f} MB/s  files={f} errors={e}")
        last_b, last_t = b, now


def start_load(host, port, path, streams, log=None, timeout=15.0):
    log = log or (lambda m: print(f"{ts()} {m}", flush=True))
    stop, stats = threading.Event(), Stats()
    threads = [threading.Thread(target=stream, args=(i, host, port, path, stats, stop, log, timeout), daemon=True)
               for i in range(streams)]
    threads.append(threading.Thread(target=reporter, args=(stats, stop, log), daemon=True))
    for t in threads:
        t.start()
    return stop, threads, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="WiFi address of the device for repro 1")
    ap.add_argument("--port", type=int, default=21)
    ap.add_argument("--path", default="/USB1/amiga64/wb-snap.bin")
    ap.add_argument("--streams", type=int, default=2)
    ap.add_argument("--duration", type=float, default=30.0, help="seconds; 0 = until Ctrl-C")
    a = ap.parse_args()
    stop, threads, stats = start_load(a.host, a.port, a.path, a.streams)
    try:
        t_end = time.monotonic() + a.duration if a.duration else None
        while t_end is None or time.monotonic() < t_end:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    stop.set()
    for t in threads:
        t.join(timeout=5)
    print(f"{ts()} total {stats.bytes} B, files {stats.files}, errors {stats.errors} {stats.last_error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
