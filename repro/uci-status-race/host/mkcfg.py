#!/usr/bin/env python3
"""Patch the config block of probe-*.prg and write a new PRG.

  mkcfg.py prebuilt/probe-recheck.prg out.prg --host 192.0.2.10 --port 18444 --size 262144 --conns 40

The config block sits at $0810 inside the PRG image (see probe.asm), so any way of loading a PRG works; nothing has
to be written to the C64 afterwards. --wait is the per-reply budget in units of 65536 polls of $DF1C.
"""
import argparse
import struct
import sys

LOAD = 0x0801
NCONN, TARGET, TMO, OPENLEN, OPENCMD = 0x0810, 0x0812, 0x0815, 0x0816, 0x0820


def patch(prg, host, port, size, conns, wait):
    cmd = bytes([0x03, 0x07, port & 0xFF, port >> 8]) + host.encode("ascii") + b"\x00"
    if len(cmd) > 64:
        raise ValueError("host name too long")
    if not 0 <= size < 1 << 24 or not 0 <= conns < 1 << 16 or not 1 <= wait <= 255:
        raise ValueError("size < 16 MiB, conns < 65536, wait 1..255")
    if int.from_bytes(prg[:2], "little") != LOAD:
        raise ValueError("not a probe PRG (load address)")
    img = bytearray(prg)

    def put(addr, data):
        off = 2 + addr - LOAD
        img[off:off + len(data)] = data
    put(NCONN, struct.pack("<H", conns))
    put(TARGET, size.to_bytes(3, "little"))
    put(TMO, bytes([wait]))
    put(OPENLEN, bytes([len(cmd)]))
    put(OPENCMD, cmd)
    return bytes(img)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--host", required=True, help="address of the machine running host/sender.py")
    ap.add_argument("--port", type=int, default=18444)
    ap.add_argument("--size", type=int, default=262144, help="payload bytes per connection (sender.py must send the same)")
    ap.add_argument("--conns", type=int, default=40, help="connections to make; 0 = until you stop the machine")
    ap.add_argument("--wait", type=int, default=8, help="per-reply wait budget, units of 65536 polls (default 8); raise it if a slow reply times out")
    a = ap.parse_args()
    out = patch(open(a.src, "rb").read(), a.host, a.port, a.size, a.conns, a.wait)
    open(a.dst, "wb").write(out)
    print("wrote %s (%d bytes)" % (a.dst, len(out)))


if __name__ == "__main__":
    sys.exit(main())
