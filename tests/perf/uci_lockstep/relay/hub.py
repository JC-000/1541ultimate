"""Relay hub: pairs one waiting side with one arriving side and forwards per-tick bytes.

See side.py for the side interface and the tick numbering contract.

Pairing and room codes
----------------------
* A C64 that HOSTs calls ``open_room``. The hub issues a 4-character code from the room
  alphabet ``ABCDEFGHJKLMNPQRSTUVWXYZ23456789`` (or takes the one given) and keeps the side
  waiting. Codes in ``reserved_codes`` (the client's APP, "LS64") are never issued.
* An arriving side calls ``join(side, code)``. With a code it pairs with that room. With
  ``code=None`` it pairs with the oldest waiting room ("default pairing", on unless
  ``default_pairing=False``).

Forwarding
----------
Bytes go straight through: ``side_ticks(a, first, data)`` -> ``b.send_ticks(first, data)``.
The hub checks continuity (first must be the next expected tick) and the skew between the two
streams: in lockstep neither C64 can be more than (its delay + its ring) ticks ahead of the
other, so a skew above ``max_skew`` (default 128) means a broken side and ends the session.

Digests: every tick k with (k & 0xFF) == 0xFF carries both C64s' state digest. The hub
compares the two bytes, logs ``digest_ok`` / ``digest_mismatch`` and counts them. It does not
end the session on a mismatch unless ``end_on_desync`` is set: both C64s detect it themselves
and end at the same tick, which is the cleaner end.

Delay
-----
Each C64's input delay must cover the one-way latency of its bytes to the other C64, i.e. both
legs. ``advised_delay`` (also in SessionStart) is delay_for_rtt(my leg + partner leg);
``update_latency`` pushes each partner's current leg RTT to the other side. run_pair.py fixes
the delay instead (--delay), so every firmware build is measured with the same one.
"""

from __future__ import annotations

import itertools
import logging
import random
import time
from dataclasses import dataclass, field
from collections.abc import Callable, Iterable

from .logfmt import slog
from .side import EndReason, SessionStart, Side, delay_for_rtt, is_digest_tick

log = logging.getLogger("relay.hub")

ROOM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LEN = 4


@dataclass
class _Room:
    code: str
    side: Side
    opened: float


@dataclass
class _Session:
    sid: int
    room: str | None
    p1: Side                      # waited
    p2: Side                      # arrived
    started: float
    rx: dict[Side, int] = field(default_factory=dict)        # next expected tick per side
    digests: dict[int, dict[Side, int]] = field(default_factory=dict)
    digest_ok: int = 0
    digest_bad: int = 0
    ended: bool = False

    def other(self, side: Side) -> Side:
        return self.p2 if side is self.p1 else self.p1


class Hub:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 rng: random.Random | None = None,
                 default_pairing: bool = True,
                 reserved_codes: Iterable[str] = ("LS64",),
                 max_skew: int = 128,
                 end_on_desync: bool = False,
                 delay_extra_us: int = 0) -> None:
        self.clock = clock
        self.rng = rng or random.SystemRandom()
        self.default_pairing = default_pairing
        self.reserved_codes = {c.upper() for c in reserved_codes}
        self.max_skew = max_skew
        self.end_on_desync = end_on_desync
        self.delay_extra_us = delay_extra_us
        self._rooms: dict[str, _Room] = {}          # insertion order = waiting order
        self._by_side: dict[Side, _Session] = {}
        self._sids = itertools.count(1)
        self.sessions_started = 0
        self.sessions_ended: list[dict] = []         # summaries, newest last

    # ---- rooms ---------------------------------------------------------------------------
    def _new_code(self) -> str:
        for _ in range(1000):
            code = "".join(self.rng.choice(ROOM_ALPHABET) for _ in range(CODE_LEN))
            if code not in self._rooms and code not in self.reserved_codes:
                return code
        raise RuntimeError("room codes exhausted")

    @staticmethod
    def normalize_code(code: str) -> str:
        code = code.strip().upper()
        if len(code) != CODE_LEN or any(c not in ROOM_ALPHABET for c in code):
            raise ValueError(f"bad room code {code!r}")
        return code

    def open_room(self, side: Side, code: str | None = None) -> str:
        """Make ``side`` wait for a partner; returns the room code."""
        if side in self._by_side:
            raise ValueError("side already in a session")
        self.leave(side)
        if code is None:
            code = self._new_code()
        else:
            code = self.normalize_code(code)
            if code in self._rooms:
                raise ValueError(f"room {code} is taken")
        self._rooms[code] = _Room(code, side, self.clock())
        slog(log, "room_open", room=code, side=side.name, kind=side.kind)
        return code

    def leave(self, side: Side) -> None:
        for code, room in list(self._rooms.items()):
            if room.side is side:
                del self._rooms[code]
                slog(log, "room_close", room=code, side=side.name)

    def waiting(self) -> list[str]:
        return list(self._rooms)

    def room_of(self, side: Side) -> str | None:
        """The code of the room ``side`` is waiting in, or None."""
        return next((c for c, r in self._rooms.items() if r.side is side), None)

    def _find_room(self, code: str | None) -> _Room | None:
        if code is None:
            if not self.default_pairing:
                return None
            return next(iter(self._rooms.values()), None)
        try:
            code = self.normalize_code(code)
        except ValueError:
            return None
        return self._rooms.get(code)

    def can_join(self, code: str | None = None) -> bool:
        return self._find_room(code) is not None

    def expected_remote_rtt(self, code: str | None = None) -> int | None:
        """Leg RTT of the side that join(code) would pair with now."""
        room = self._find_room(code)
        return room.side.leg_rtt_us() if room else None

    def join(self, side: Side, code: str | None = None) -> bool:
        """Pair ``side`` with a waiting room now. Starts the session on both sides."""
        if side in self._by_side:
            return False
        room = self._find_room(code)
        if room is None or room.side is side:
            slog(log, "join_refused", logging.WARNING, side=side.name,
                 room=code if code is not None else "-", reason=EndReason.NO_PARTNER)
            return False
        del self._rooms[room.code]
        sess = _Session(next(self._sids), room.code, room.side, side, self.clock())
        sess.rx[room.side] = 0
        sess.rx[side] = 0
        self._by_side[room.side] = sess
        self._by_side[side] = sess
        self.sessions_started += 1
        r1, r2 = room.side.leg_rtt_us(), side.leg_rtt_us()
        slog(log, "session_start", sid=sess.sid, room=room.code, p1=room.side.name,
             p2=side.name, p1_rtt_us=r1, p2_rtt_us=r2)
        for me, other, player, my_rtt, other_rtt in ((room.side, side, 1, r1, r2),
                                                     (side, room.side, 2, r2, r1)):
            info = SessionStart(sess.sid, player, room.code, other.kind,
                                self._delay(my_rtt, other_rtt), other_rtt)
            me.session = info
            me.start_session(info)
            if sess.ended:          # a side ended inside start_session
                break
        return not sess.ended

    # ---- forwarding ----------------------------------------------------------------------
    def side_ticks(self, side: Side, first_tick: int, data: bytes) -> None:
        sess = self._by_side.get(side)
        if sess is None or sess.ended or not data:
            return
        expect = sess.rx[side]
        if first_tick != expect:
            slog(log, "tick_gap", logging.ERROR, sid=sess.sid, side=side.name,
                 expected=expect, got=first_tick)
            self._end(sess, side, EndReason.PROTOCOL)
            return
        other = sess.other(side)
        sess.rx[side] = expect + len(data)
        if abs(sess.rx[side] - sess.rx[other]) > self.max_skew:
            slog(log, "skew", logging.ERROR, sid=sess.sid, side=side.name,
                 mine=sess.rx[side], other=sess.rx[other])
            self._end(sess, side, EndReason.OVERFLOW)
            return
        # digest ticks inside this range
        k = first_tick | 0xFF
        while k < first_tick + len(data):
            if is_digest_tick(k):
                self._digest(sess, side, k, data[k - first_tick])
                if sess.ended:
                    return
            k += 0x100
        other.send_ticks(first_tick, bytes(data))

    def _digest(self, sess: _Session, side: Side, tick: int, value: int) -> None:
        d = sess.digests.setdefault(tick, {})
        d[side] = value
        if len(d) < 2:
            return
        del sess.digests[tick]
        a, b = d[sess.p1], d[sess.p2]
        if a == b:
            sess.digest_ok += 1
            slog(log, "digest_ok", logging.DEBUG, sid=sess.sid, tick=tick, digest=f"{a:02x}")
        else:
            sess.digest_bad += 1
            slog(log, "digest_mismatch", logging.WARNING, sid=sess.sid, tick=tick,
                 p1=f"{a:02x}", p2=f"{b:02x}")
            if self.end_on_desync:
                self._end(sess, None, EndReason.DESYNC)

    def side_ended(self, side: Side, reason: str) -> None:
        sess = self._by_side.get(side)
        if sess is None:
            self.leave(side)
            return
        if not sess.ended:
            self._end(sess, side, reason)

    def _end(self, sess: _Session, by: Side | None, reason: str) -> None:
        sess.ended = True
        for s in (sess.p1, sess.p2):
            self._by_side.pop(s, None)
        summary = {"sid": sess.sid, "room": sess.room, "by": by.name if by else "hub",
                   "reason": reason, "p1_ticks": sess.rx[sess.p1], "p2_ticks": sess.rx[sess.p2],
                   "digest_ok": sess.digest_ok, "digest_bad": sess.digest_bad,
                   "seconds": round(self.clock() - sess.started, 3)}
        self.sessions_ended.append(summary)
        slog(log, "session_end", **summary)
        for s in (sess.p1, sess.p2):
            if s is by:
                continue
            try:
                s.end_session(EndReason.PARTNER if by is not None else reason)
            except Exception:  # pragma: no cover - a side must not take the hub down
                log.exception("end_session failed for %s", s.name)

    def session_of(self, side: Side) -> _Session | None:
        return self._by_side.get(side)

    # ---- latency / delay -----------------------------------------------------------------
    def _delay(self, a: int | None, b: int | None) -> int:
        if a is None and b is None:
            return delay_for_rtt(None)
        return delay_for_rtt((a or 0) + (b or 0) + self.delay_extra_us)

    def advised_delay(self, side: Side) -> int:
        sess = self._by_side.get(side)
        if sess is None:
            return delay_for_rtt(None)
        return self._delay(side.leg_rtt_us(), sess.other(side).leg_rtt_us())

    def update_latency(self) -> None:
        """Push each partner's current leg RTT to the other side."""
        seen = set()
        for sess in list(self._by_side.values()):
            if sess.sid in seen or sess.ended:
                continue
            seen.add(sess.sid)
            r1, r2 = sess.p1.leg_rtt_us(), sess.p2.leg_rtt_us()
            sess.p1.set_remote_leg_rtt(r2)
            sess.p2.set_remote_leg_rtt(r1)

    def shutdown(self) -> None:
        for sess in {id(s): s for s in self._by_side.values()}.values():
            if not sess.ended:
                self._end(sess, None, EndReason.SHUTDOWN)
        for room in list(self._rooms.values()):
            self.leave(room.side)
            try:
                room.side.end_session(EndReason.SHUTDOWN)
            except Exception:  # pragma: no cover
                log.exception("end_session failed for %s", room.side.name)
