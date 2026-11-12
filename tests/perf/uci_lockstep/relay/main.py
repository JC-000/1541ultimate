"""Run the relay: two C64s pair through a room code and play one lockstep session.

    python3 -m relay --bind 192.0.2.1 --host-code TEST --delay 5 \\
        --wan-delay-ms 17.5 --wan-jitter-ms 2.5 --wan-loss 0.01 --summary relay.json

Every C64 that HOSTs gets the room ``--host-code``; the other C64 JOINs that code. The relay
forwards each tick's input byte, compares the two C64s' digests, and can put a simulated WAN
on each C64's leg (``--wan-*``: per leg and per direction, so the one-way delay between the two
C64s is twice ``--wan-delay-ms``). It runs until SIGINT/SIGTERM or ``--seconds``, then ends any
open session and writes ``--summary``: the sessions with their digest counts, each C64 client,
and the WAN statistics.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path

from . import netem
from .c64_side import DEFAULT_PORT, start_c64_endpoint
from .hub import Hub
from .logfmt import JsonFormatter, TextFormatter, slog

log = logging.getLogger("relay")


def setup_logging(level: str, fmt: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper()))


async def serve(args: argparse.Namespace) -> int:
    hub = Hub()
    em = netem.from_args(args)
    server = await start_c64_endpoint(hub, args.bind, args.port, delay=args.delay,
                                      netem=em, host_code=args.host_code or None)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass
    t0 = loop.time()
    try:
        while (args.seconds <= 0 or loop.time() - t0 < args.seconds) and not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.25)
            except TimeoutError:
                pass
    finally:
        hub.shutdown()          # end a session still open: its digest summary
        server.close()
    slog(log, "relay_done", sessions=len(hub.sessions_ended), wan=em.stats)
    if args.summary:
        Path(args.summary).write_text(json.dumps({
            "hub_sessions": hub.sessions_ended,
            "c64_clients": [{"addr": f"{c.addr[0]}:{c.addr[1]}", "rx": c.n_rx, "tx": c.n_tx,
                             "rtt_us": c.rtt_us, "delay": c.delay}
                            for c in server.relay.clients.values()],
            "relay_dropped": server.relay.dropped,
            "wan": {"delay_ms": em.delay_ms, "jitter_ms": em.jitter_ms, "loss": em.loss,
                    "reorder": em.reorder, **em.stats}}, indent=1))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m relay", description=__doc__.split("\n\n")[0])
    p.add_argument("--bind", default="0.0.0.0", help="address to listen on")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--host-code", default="TEST",
                   help="room code every HOST gets (alphabet: A-Z without I and O, 2-9)")
    p.add_argument("--delay", type=int, default=None,
                   help="fixed input delay for both C64s, 1..24 (default: from the RTT)")
    p.add_argument("--seconds", type=float, default=0, help="stop after this long (0 = never)")
    p.add_argument("--summary", default="", help="write the JSON summary here at exit")
    p.add_argument("--log-level", default="info")
    p.add_argument("--log-format", choices=("text", "json"), default="text")
    netem.add_args(p)
    args = p.parse_args(argv)
    setup_logging(args.log_level, args.log_format)
    return asyncio.run(serve(args))
