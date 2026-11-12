"""The interface between the relay hub and one C64's connection to it (a "side").

The hub (``hub.py``) pairs two sides into a session and forwards per-tick input bytes between
them. The hub never touches sockets; sides never talk to each other. ``c64_side.py`` is the
only kind of side here.

Everything is synchronous and single-threaded (one asyncio loop): side -> hub calls and hub ->
side calls are plain method calls that must not block and must not raise into the caller.

Tick numbering (must match client/session.s)
--------------------------------------------
* Stream tick k (k = 0, 1, 2, ... as an unbounded Python int on the hub) is the C64's input
  byte for game tick k. Game ticks -5..-1 carry no bytes and are never transmitted; tick 0 is
  the first byte of each C64's stream.
* Digest ticks: every tick k with (k & 0xFF) == 0xFF carries a state digest instead of buttons
  (digest_state of the state at the start of tick k - 32, low byte $DF; see
  client/digest.inc, which allows delays up to 31). Both C64s send it in the same slot; the hub
  forwards it like any other byte and compares the two.
* Each side delivers its C64's bytes to the hub **in order, without gaps or duplicates**,
  starting at tick 0. Making its own leg reliable (acks, retransmits, batching) is the side's
  job. Likewise ``send_ticks`` is called with contiguous, never-repeated ranges starting at 0.

Roles
-----
The side that waits (``hub.open_room``) is player 1, the side that arrives (``hub.join``) is
player 2.

Lifecycle
---------
    side -> hub.open_room(side, code=None) -> code    wait for a partner (hub issues a code)
    side -> hub.join(side, code=None)      -> bool    pair now; False if nobody to pair with
    side -> hub.can_join(code=None)        -> bool    would join() succeed right now?
    side -> hub.leave(side)                           stop waiting (before a session starts)
    hub  -> side.start_session(info)                  both sides, synchronously inside join()
    side -> hub.side_ticks(side, first, data)         C64 bytes for ticks first..first+n-1
    hub  -> side.send_ticks(first, data)              the partner's bytes, same numbering
    side -> hub.side_ended(side, reason)              this side's C64/link is gone
    hub  -> side.end_session(reason)                  partner gone or hub ended it; the side
                                                      hangs up its leg and must NOT call
                                                      hub.side_ended afterwards (ignored anyway)

Latency
-------
    side.leg_rtt_us()            this leg's round trip relay <-> C64, in us, including any
                                 batching/polling the side adds; None while unknown
    side.set_remote_leg_rtt(us)  the hub reports the *partner's* leg RTT (periodically and at
                                 start); a side may use it to pick its C64's input delay.
"""

from __future__ import annotations

import abc
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .hub import Hub

# One tick at 60 Hz.
TICK_US = 16_667
# Fixed per-path margin in delay_for_rtt.
DELAY_MARGIN_US = 9_000
MIN_DELAY = 1
MAX_DELAY = 5
DIGEST_MASK = 0xFF  # tick k is a digest tick when (k & DIGEST_MASK) == DIGEST_MASK


def delay_for_rtt(rtt_us: int | None) -> int:
    """Input delay (ticks) that covers a path with this round trip:
    ceil((rtt/2 + 9 ms) / 16.667 ms), clamped to 1..5. None -> 2."""
    if rtt_us is None:
        return 2
    d = math.ceil((max(0, rtt_us) / 2 + DELAY_MARGIN_US) / TICK_US)
    return max(MIN_DELAY, min(MAX_DELAY, d))


def is_digest_tick(tick: int) -> bool:
    return tick >= 0 and (tick & DIGEST_MASK) == DIGEST_MASK


class EndReason:
    """Why a side or a session ended (plain strings, used in logs)."""

    BYE = "bye"              # the C64 hung up explicitly
    TIMEOUT = "timeout"      # leg silent too long
    PARTNER = "partner"      # the other side ended
    DESYNC = "desync"        # hub saw different digests (only if the hub is told to act on it)
    OVERFLOW = "overflow"    # a side's backlog grew past any lockstep-plausible size
    PROTOCOL = "protocol"    # malformed / impossible input from the C64's leg
    MISMATCH = "mismatch"    # greeting / version does not match
    SHUTDOWN = "shutdown"    # relay is stopping
    NO_PARTNER = "no_partner"  # arrived with nobody to pair with


@dataclass(frozen=True)
class SessionStart:
    session_id: int            # hub's id for logs
    player: int                # 1 = waited (open_room), 2 = arrived (join)
    room: str | None           # room code, None for the default (code-less) pairing
    partner_kind: str          # "c64"
    advised_delay: int         # 1..5: delay_for_rtt(my leg + partner leg), 2 if unknown
    remote_leg_rtt_us: int | None


class Side(abc.ABC):
    """Base class every relay side implements."""

    #: "c64" (free-form for test doubles).
    kind: str = "?"

    def __init__(self, hub: Hub, name: str) -> None:
        self.hub = hub
        self.name = name          # for logs, e.g. "c64 192.0.2.7:4096 n=1a2b"
        self.session: SessionStart | None = None

    # ---- hub -> side -----------------------------------------------------------------------
    @abc.abstractmethod
    def start_session(self, info: SessionStart) -> None:
        """Paired: from now on hub.side_ticks / send_ticks flow. Called inside hub.join()."""

    @abc.abstractmethod
    def send_ticks(self, first_tick: int, data: bytes) -> None:
        """Queue the partner's bytes for ticks first_tick.. toward this side's C64."""

    @abc.abstractmethod
    def end_session(self, reason: str) -> None:
        """Hang up this leg (partner gone / relay stopping). Must not call hub.side_ended."""

    def set_remote_leg_rtt(self, rtt_us: int | None) -> None:  # noqa: B027 - optional hook
        """The partner leg's RTT estimate (us). Default: ignore."""

    # ---- queries ---------------------------------------------------------------------------
    @abc.abstractmethod
    def leg_rtt_us(self) -> int | None:
        """This leg's round trip (relay <-> C64, us), incl. any batching delay; None if
        unknown yet."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.name}>"
