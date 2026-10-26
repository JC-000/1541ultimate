#!/usr/bin/env python3
"""Offline check of the probe PRGs in a 6502 simulator (no device, no network). Run from anywhere:

  python3 selftest.py            test prebuilt/*.prg
  python3 selftest.py --build    assemble probe.asm first (needs 64tass on PATH or --64tass PATH)

The mock Command Interface here has a switch that reads state 11 on the first $DF1C sample after the DATA_ACC that
moves a reply to its last block. That is the symptom the probe looks for, injected on purpose: it shows the PRG's
bookkeeping and the two build variants behave as documented. It says nothing about whether the hardware does it.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.join(HERE, "host"))
import sim6502 as sim   # noqa: E402
import mkcfg            # noqa: E402

DONE, ERR, CONNS, READS, LASTBLK, EVENTS, ACTED, STILL, DIS, MISM, SIG, LOGY, LAG = (
    0xC002, 0xC003, 0xC010, 0xC012, 0xC015, 0xC018, 0xC01A, 0xC01C, 0xC01E, 0xC020, 0xC022, 0xC023, 0xC024)


class SkewUci(sim.MockUci):
    def __init__(self, *a, skew_every=0, lag_every=0, **k):
        super().__init__(*a, **k)
        self.skew_every, self.n, self.skew_next = skew_every, 0, False
        self.lag_every, self.ln, self.lag_next = lag_every, 0, False

    def _accept(self):
        before = self.state
        super()._accept()
        if self.skew_every and before == 3 and self.state == 2:
            self.n += 1
            if self.n % self.skew_every == 0:
                self.skew_next = True
        if self.lag_every and before in (2, 3) and self.state in (2, 3) and before != self.state:
            self.ln += 1
            if self.ln % self.lag_every == 0:
                self.lag_next = True

    def read(self, a):
        v = super().read(a)
        if a == 0xDF1C and self.skew_next and self.state == 2:
            self.skew_next = False
            return (v & ~0x30) | 0x30
        if a == 0xDF1C and self.lag_next and self.state in (2, 3):
            self.lag_next = False
            return v & ~0xC0                # state already new, DATA_AV / STAT_AV one clock behind
        return v


def run(prg, uci, size, conns):
    img = mkcfg.patch(open(prg, "rb").read(), "192.0.2.10", 18444, size, conns, 1)
    m = sim.Machine(uci)
    m.load_prg(img)
    m.ram[0xFFD2] = 0x60                    # CHROUT: rts
    m.cpu.pc = 0x080D
    how = m.run_until(lambda mm: False, limit=200_000_000)
    assert how == "parked", how
    return m.ram


def w(r, a, n):
    return int.from_bytes(r[a:a + n], "little")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--64tass", dest="tass", default="64tass")
    a = ap.parse_args()
    if a.build:
        for act, name in ((1, "probe-recheck"), (0, "probe-hang")):
            subprocess.run([a.tass, "-a", "-D", "ACT=%d" % act, os.path.join(HERE, "probe.asm"),
                            "-o", os.path.join(HERE, "prebuilt", name + ".prg")], check=True, stdout=subprocess.DEVNULL)
    recheck = os.path.join(HERE, "prebuilt", "probe-recheck.prg")
    hang = os.path.join(HERE, "prebuilt", "probe-hang.prg")

    # config round trip
    img = mkcfg.patch(open(recheck, "rb").read(), "192.0.2.10", 18444, 262144, 40, 8)
    off = 2 + mkcfg.OPENCMD - mkcfg.LOAD
    assert img[off:off + 15] == bytes([3, 7, 18444 & 0xFF, 18444 >> 8]) + b"192.0.2.10\x00"
    print("config block ok")

    # no skew: nothing to report, everything checked
    r = run(recheck, SkewUci(payload=20000), 20000, 3)
    assert r[DONE] == 0x5A and w(r, CONNS, 2) == 3 and w(r, EVENTS, 2) == 0 and w(r, MISM, 2) == 0 and r[SIG] == 0xE1
    reads, last = w(r, READS, 3), w(r, LASTBLK, 3)
    assert reads == 3 * 14 and last == reads + 3 * 3, (reads, last)   # 20000 bytes = 14 READs; OPEN, WRITE, CLOSE are last blocks too
    print("clean: done, %d READs, %d last blocks, 0 events, 0 mismatches" % (reads, last))

    # corrupt byte: counted, run goes on
    r = run(recheck, SkewUci(payload=20000, corrupt_at=5000), 20000, 1)
    assert r[DONE] == 0x5A and w(r, MISM, 2) == 1
    print("corrupt byte: counted")

    # injected skew, re-check build: every event re-read as 10 and the run completes
    r = run(recheck, SkewUci(payload=20000, skew_every=3), 20000, 3)
    ev = w(r, EVENTS, 2)
    assert r[DONE] == 0x5A and ev > 0 and w(r, ACTED, 2) == ev and w(r, STILL, 2) == 0 and w(r, MISM, 2) == 0
    assert w(r, DIS, 2) >= ev and r[LOGY] == 8 * min(ev, 16)
    assert r[0xC040] & 0x30 == 0x30 and r[0xC041] & 0x30 == 0x20
    print("skew, recheck build: %d events, all re-read as 10, run completed" % ev)

    # injected lag of bits 7/6 (clean reads): confirmed away by the re-read build, counted
    r = run(recheck, SkewUci(payload=20000, lag_every=3), 20000, 3)
    assert r[DONE] == 0x5A and w(r, LAG, 2) > 0 and w(r, MISM, 2) == 0 and w(r, EVENTS, 2) == 0
    print("lag of bits 7/6, recheck build: %d blocks, run completed, no payload loss" % w(r, LAG, 2))
    r = run(hang, SkewUci(payload=20000, lag_every=3), 20000, 3)
    print("lag of bits 7/6, hang build: DONE=%02X ERR=%d LAG=%d MISM=%d" % (r[DONE], r[ERR], w(r, LAG, 2), w(r, MISM, 2)))

    # injected skew, hang build: the first event is believed, the reply never comes, the wait times out
    r = run(hang, SkewUci(payload=20000, skew_every=3), 20000, 3)
    assert r[DONE] == 0xEE and r[ERR] == 11 and w(r, EVENTS, 2) >= 1
    print("skew, hang build: stopped with ERR=11 after %d event(s)" % w(r, EVENTS, 2))
    print("ok")


if __name__ == "__main__":
    sys.exit(main())
