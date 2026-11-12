#!/usr/bin/env python3
"""BENCH ONLY (repro for #1079, never for upstream): read the module's reply backlog counter, or queue a burst, over the UCI.

    python3 bench-repro/1079-reply-backlog/txq.py -H <device> --burst 11               # 11 frames of 4 bytes, back to back
    python3 bench-repro/1079-reply-backlog/txq.py -H <device> --burst 11 --size 1000   # for a throughput figure
    python3 bench-repro/1079-reply-backlog/txq.py -H <device> --reset                  # clear q_max and frames
    python3 bench-repro/1079-reply-backlog/txq.py -H <device>                          # read only

Uses the repo's own tests/e2e/lib/uci.py, as net_target_test.py does. Leaves the Command Interface setting Enabled."""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(next(p for p in Path(__file__).resolve().parents
                            if (p / "tests" / "lib").is_dir()) / "tests" / "lib"))
import bootstrap  # noqa: E402,F401
import cli  # noqa: E402
import targets  # noqa: E402
from api import UltimateApi  # noqa: E402
from uci import TARGET_NETWORK, Uci  # noqa: E402

NET_CMD_BENCH_TXQ = 0xE7
RESET = 0x80000000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    cli.add_device_arguments(parser, password=None, timeout=30.0, colour=False)
    parser.add_argument("--burst", type=int, default=0, help="frames to queue back to back (0 = only read)")
    parser.add_argument("--size", type=int, default=0, help="bytes per frame, 4..1500 (0 = 4)")
    parser.add_argument("--reset", action="store_true", help="clear the counters first")
    args = parser.parse_args()
    arg = (args.burst & 0xFFFF) | ((args.size & 0x7FFF) << 16) | (RESET if args.reset else 0)
    device = UltimateApi(targets.parse(args.host).device, args.password, args.timeout)
    device.configs.set("C64 and Cartridge Settings", "Command Interface", "Enabled")
    uci = Uci(device.machine, 15.0)
    uci.release()
    tx = uci.transact(bytes([TARGET_NETWORK, NET_CMD_BENCH_TXQ]) + struct.pack("<I", arg))
    print(f"arg 0x{arg:08X}  status {tx.status_text!r}  data {tx.data.hex(' ')}")
    if len(tx.data) >= 24:
        esp_err, sent, q_max, left, drain_us, frames = struct.unpack("<iIIIII", tx.data[:24])
        print(f"esp_err {esp_err}  sent {sent}  q_max {q_max}  left {left}  drain_us {drain_us}  frames {frames}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
