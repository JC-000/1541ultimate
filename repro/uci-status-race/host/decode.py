#!/usr/bin/env python3
"""Decode the probe's result block ($C000..$C0BF, 192 bytes).

  decode.py dump.bin                 a 192 byte file (a memory dump from any tool)
  decode.py --device HOST            read it with one GET of the REST API's machine:readmem (read-only)
"""
import argparse
import sys
import urllib.request

NAMES = {0x5A: "finished", 0xEE: "stopped on error", 0: "running"}
ERRS = {0: "none", 2: "OPEN_TCP failed", 4: "WRITE failed", 5: "READ failed", 7: "CLOSE failed",
        11: "timeout waiting for a reply (the hang)", 13: "interface not idle"}


def le(b):
    return int.from_bytes(b, "little")


def decode(m):
    if len(m) < 192 or m[0x22] != 0xE1:
        raise ValueError("not a probe result block (signature $E1 missing at $C022)")
    out = ["state      %s (DONE=%02X)" % (NAMES.get(m[2], "?"), m[2]),
           "error      %s (ERR=%02d)" % (ERRS.get(m[3], "?"), m[3]),
           "connections %d" % le(m[0x10:0x12]),
           "READs      %d" % le(m[0x12:0x15]),
           "last blocks %d" % le(m[0x15:0x18]),
           "events     %d   (last block whose first sample said 11)" % le(m[0x18:0x1A]),
           "  re-read said 10: %d   still 11: %d" % (le(m[0x1A:0x1C]), le(m[0x1C:0x1E])),
           "first-sample vs post-drain state differ: %d" % le(m[0x1E:0x20]),
           "payload mismatches: %d" % le(m[0x20:0x22])]
    n = min(m[0x23] // 8, 16)
    if n:
        out.append("event log (sample, re-read 1,2,3, block bytes, READ#):")
    for i in range(n):
        e = m[0x40 + 8 * i:0x48 + 8 * i]
        out.append("  $%02X  $%02X $%02X $%02X  %4d  %d" % (e[0], e[1], e[2], e[3], le(e[4:6]), le(e[6:8])))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?")
    ap.add_argument("--device")
    a = ap.parse_args()
    if a.device:
        url = "http://%s/v1/machine:readmem?address=C000&length=192" % a.device
        data = urllib.request.urlopen(url, timeout=10).read()
    elif a.dump:
        data = open(a.dump, "rb").read()
    else:
        ap.error("give a dump file or --device")
    print(decode(data))


if __name__ == "__main__":
    sys.exit(main())
