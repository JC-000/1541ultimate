"""Simulated WAN on each C64's leg to the relay: one-way delay, jitter and loss, both ways.

Applied to datagrams between the C64 and the relay (``C64Server``), so the C64's LOBBY RTT,
the relay's auto delay and the session's SEQ accounting all see the same network the C64 sees.
Each direction holds ``delay_ms`` +- ``jitter_ms`` (uniform) and drops ``loss`` (0..1) of the
datagrams independently. Order is kept by default (a datagram never leaves before the one
before it in the same direction), as on a single internet path; ``reorder=True`` lets jitter
reorder them.

Seeded, so a run is repeatable given the same arrival times.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from collections.abc import Callable


@dataclass
class Netem:
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    loss: float = 0.0
    reorder: bool = False
    seed: int = 1
    _rnd: random.Random = field(init=False, repr=False)
    _last: dict = field(init=False, repr=False, default_factory=dict)
    stats: dict = field(init=False, default_factory=lambda: {
        "in": 0, "in_dropped": 0, "out": 0, "out_dropped": 0})

    def __post_init__(self) -> None:
        if not 0.0 <= self.loss < 1.0:
            raise ValueError("loss must be in [0, 1)")
        if self.delay_ms < 0 or self.jitter_ms < 0:
            raise ValueError("delay and jitter must be >= 0")
        self._rnd = random.Random(self.seed)

    @property
    def active(self) -> bool:
        return self.delay_ms > 0 or self.jitter_ms > 0 or self.loss > 0

    def hold_s(self, direction: str, now: float) -> float | None:
        """Seconds to hold one datagram going ``direction`` ("in": C64 -> relay, "out":
        relay -> C64) that arrives at loop time ``now``; None = drop it."""
        self.stats[direction] += 1
        if self.loss and self._rnd.random() < self.loss:
            self.stats[direction + "_dropped"] += 1
            return None
        d = self.delay_ms
        if self.jitter_ms:
            d += self._rnd.uniform(-self.jitter_ms, self.jitter_ms)
        at = now + max(0.0, d) / 1000.0
        if not self.reorder:
            at = max(at, self._last.get(direction, 0.0))
            self._last[direction] = at
        return at - now

    def schedule(self, loop: asyncio.AbstractEventLoop, direction: str,
                 fn: Callable[[], None]) -> None:
        """Run ``fn`` after this direction's hold, or never if the datagram is dropped."""
        hold = self.hold_s(direction, loop.time())
        if hold is None:
            return
        if hold <= 0:
            fn()
        else:
            loop.call_later(hold, fn)

    def describe(self) -> str:
        return (f"delay {self.delay_ms:g} ms +- {self.jitter_ms:g} ms, loss {self.loss:.1%}"
                f"{', reorder' if self.reorder else ''} (each way)")


def add_args(p) -> None:
    """argparse options shared by the relay entry points."""
    p.add_argument("--wan-delay-ms", type=float, default=0.0,
                   help="simulated one-way delay on each C64 leg, each direction")
    p.add_argument("--wan-jitter-ms", type=float, default=0.0,
                   help="uniform +- jitter on that delay")
    p.add_argument("--wan-loss", type=float, default=0.0,
                   help="fraction of datagrams dropped, each direction independently (0..1)")
    p.add_argument("--wan-reorder", action="store_true",
                   help="let jitter reorder datagrams (default: keep order)")
    p.add_argument("--wan-seed", type=int, default=1)


def from_args(a) -> Netem:
    return Netem(delay_ms=a.wan_delay_ms, jitter_ms=a.wan_jitter_ms, loss=a.wan_loss,
                 reorder=a.wan_reorder, seed=a.wan_seed)
