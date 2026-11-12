"""The relay's C64 protocol (the wire format is in ../README.md) on UDP 6520.

``C64Relay`` is the protocol engine, synchronous and socket-free: ``datagram(addr, data)``
returns the one reply the protocol owes (or None), ``expire()`` drops silent clients. Every C64
client (keyed by its source address) is a ``C64Side`` in the hub (side.py). ``start_c64_endpoint``
wraps it in an asyncio UDP endpoint.

Rules: the relay never sends unprompted, it answers every datagram exactly once.
Bytes from the C64 are handed to the hub in order, without gaps or repeats; the partner's bytes
are kept from the C64's last ACK on and resent in every TICKS reply until acknowledged.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from collections.abc import Callable

from .logfmt import slog
from .netem import Netem
from .side import TICK_US, EndReason, SessionStart, Side

log = logging.getLogger("relay.c64")

DEFAULT_PORT = 6520
PROTO = 3
APP = b"LS64"
APP_VERSION = 1

T_LOBBY, T_TICKS, T_BYE = 0x01, 0x10, 0x1F
T_STATE, T_START, T_RTICKS, T_RBYE = 0x81, 0x82, 0x90, 0x9F
OP_POLL, OP_HOST, OP_JOIN, OP_LEAVE = 0, 1, 2, 3
ST_IDLE, ST_WAITING, ST_NOROOM, ST_FULL, ST_MISMATCH, ST_BUSY = 0, 1, 2, 3, 4, 5
BYE_LOST, BYE_TIMEOUT, BYE_DESYNC, BYE_USER, BYE_RELAY = 1, 2, 3, 4, 5

WINDOW = 6                  # most stream bytes per TICKS (C64 per-frame cycle budget)
MIN_DELAY, MAX_DELAY = 1, 24
FRAME_US = TICK_US          # one 60 Hz tick
# Terms of the automatic input delay (used only without --delay; estimates).
C64_PIPE_US = 4_000         # C64 input sampled -> its datagram on the wire (<= ~3 ms of
                            # c64n_frame before the WRITE is pushed, + ~1 ms firmware send, est.)
PICKUP_US = FRAME_US        # the partner C64 takes the byte at its next frame (worst case)
JITTER_US = 5_000           # margin for host scheduling / Wi-Fi jitter
LAN_RTT_US = 2_000          # assumed network RTT of a leg we know only as "under one frame"
LOBBY_TIMEOUT = 10.0        # s of silence before a lobby client is forgotten
SESSION_TIMEOUT = 3.0       # s of silence before a session client is gone
MAX_CLIENTS = 256

_TO_WIRE = {EndReason.PARTNER: BYE_LOST, EndReason.BYE: BYE_LOST, EndReason.TIMEOUT: BYE_TIMEOUT,
            EndReason.DESYNC: BYE_DESYNC, EndReason.SHUTDOWN: BYE_RELAY, "user": BYE_USER}
_PARTNER_WHY = {EndReason.BYE: "user", EndReason.TIMEOUT: EndReason.TIMEOUT,
                EndReason.DESYNC: EndReason.DESYNC}
_FROM_WIRE = {BYE_USER: EndReason.BYE, BYE_TIMEOUT: EndReason.TIMEOUT,
              BYE_DESYNC: EndReason.DESYNC}


def unwrap8(wire: int, near: int) -> int:
    """The unbounded index with low 8 bits ``wire`` closest to ``near`` (TICKS carry the low
    bytes of ACK and FIRST; lockstep keeps them well within +-127 of what we hold)."""
    d = (wire - near) & 0xFF
    if d >= 0x80:
        d -= 0x100
    return near + d


def unwrap16(wire: int, near: int) -> int:
    """The unbounded index with low 16 bits ``wire`` closest to ``near``."""
    d = (wire - near) & 0xFFFF
    if d >= 0x8000:
        d -= 0x10000
    return near + d


def c64_net_rtt_us(rtt_frames: int) -> int:
    """The C64 leg's network RTT from the C64's LOBBY round trip in frames. The C64 reads a
    reply one frame after sending (pipelined), so 1 frame means "under a frame" (LAN)."""
    if rtt_frames <= 1:
        return LAN_RTT_US
    return (rtt_frames - 1) * FRAME_US


def auto_delay(c64_rtt_us: int | None, partner_rtt_us: int | None) -> int:
    """C64 input delay (C64 -> partner direction): the time from the C64 sampling its input
    to the partner C64 consuming that byte, in whole ticks."""
    one_way = (C64_PIPE_US + (LAN_RTT_US if c64_rtt_us is None else c64_rtt_us) / 2
               + (LAN_RTT_US if partner_rtt_us is None else partner_rtt_us) / 2
               + PICKUP_US + JITTER_US)
    return max(MIN_DELAY, min(MAX_DELAY, math.ceil(one_way / FRAME_US)))


class C64Side(Side):
    """One C64 client (one UCI socket = one source address)."""

    kind = "c64"

    def __init__(self, relay: C64Relay, addr: tuple[str, int], nonce: int) -> None:
        super().__init__(relay.hub, f"c64 {addr[0]}:{addr[1]} n={nonce:04x}")
        self.relay = relay
        self.addr = addr
        self.nonce = nonce
        self.last_heard = relay.clock()
        self.status = ST_IDLE           # sticky lobby status (NOROOM/MISMATCH until next order)
        self.room: str | None = None
        self.sid = 0                    # wire session id of the current/last session
        self.player = 0
        self.delay = 0
        self.in_session = False
        self.confirmed = False          # a TICKS with this sid arrived (stop sending START)
        self.bye_reason: int | None = None   # session over: answer with BYE
        # C64 -> hub
        self.rx_have = 0                # next C64 stream index the hub needs
        # hub -> C64: partner bytes from tx_base on
        self.tx_base = 0
        self.tx = bytearray()
        # RTT estimate: when partner byte k was first sent; ACK covering k measures it
        self.sent_at: dict[int, float] = {}
        self.rtt_us: int | None = None    # leg RTT incl. the C64's 1-frame read pipeline
        self.lobby_rtt_frames = 0            # the C64's own LOBBY round trip (0 = unknown)
        self.n_rx = 0                        # datagrams received from this C64
        self.n_tx = 0                        # replies sent to it
        self.remote_rtt_us: int | None = None

    # ---- Side ------------------------------------------------------------------------------
    def start_session(self, info: SessionStart) -> None:
        self.relay.next_sid = self.relay.next_sid % 255 + 1
        if self.relay.next_sid == self.sid:
            self.relay.next_sid = self.relay.next_sid % 255 + 1
        self.sid = self.relay.next_sid
        self.player = info.player
        fixed = self.relay.fixed_delay
        self.delay = fixed if fixed is not None else auto_delay(
            c64_net_rtt_us(self.lobby_rtt_frames), info.remote_leg_rtt_us)
        self.in_session, self.confirmed, self.bye_reason = True, False, None
        self.room = None
        self.rx_have, self.tx_base, self.tx = 0, 0, bytearray()
        self.sent_at.clear()
        slog(log, "c64_session_start", side=self.name, sid=self.sid, player=self.player,
             delay=self.delay, partner=info.partner_kind)

    def send_ticks(self, first_tick: int, data: bytes) -> None:
        if not self.in_session or first_tick != self.tx_base + len(self.tx):
            return
        self.tx += data

    def end_session(self, reason: str) -> None:
        if self.in_session:
            self.in_session = False
            if reason == EndReason.PARTNER:        # say why the partner ended, if the hub knows
                last = self.hub.sessions_ended[-1] if self.hub.sessions_ended else {}
                if self.session is not None and last.get("sid") == self.session.session_id:
                    reason = _PARTNER_WHY.get(last.get("reason"), reason)
            self.bye_reason = _TO_WIRE.get(reason, BYE_LOST)
            slog(log, "c64_session_end", side=self.name, sid=self.sid, reason=reason)
        elif self.room is not None:          # relay shutdown while waiting
            self.room = None
            self.status = ST_IDLE

    def set_remote_leg_rtt(self, rtt_us: int | None) -> None:
        self.remote_rtt_us = rtt_us

    def leg_rtt_us(self) -> int | None:
        if self.rtt_us is None and self.lobby_rtt_frames:
            return self.lobby_rtt_frames * FRAME_US
        return self.rtt_us

    # ---- protocol --------------------------------------------------------------------------
    def _end_here(self, reason: str) -> None:
        if self.in_session:
            self.in_session = False
            self.bye_reason = BYE_LOST
            self.hub.side_ended(self, reason)
            slog(log, "c64_session_end", side=self.name, sid=self.sid, reason=reason, by="c64")

    def lobby(self, seq: int, op: int, code: bytes) -> bytes:
        if self.in_session:
            if not self.confirmed:
                return self._start(seq)
            self._end_here(EndReason.BYE)    # back in its lobby: its BYEs were all lost
        if op == OP_HOST:
            if self.room is None or self.room not in self.hub.waiting():
                code = self.relay.host_code
                try:
                    self.room = self.hub.open_room(self, code)
                except ValueError as e:      # the fixed code is taken/invalid: a random one
                    slog(log, "host_code_unusable", logging.WARNING, code=code, error=str(e))
                    self.room = self.hub.open_room(self)
            self.status = ST_WAITING
        elif op == OP_JOIN:
            self.hub.leave(self)
            self.room = None
            try:
                ok = self.hub.join(self, code.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                ok = False
            if ok and self.in_session:
                return self._start(seq)
            self.status = ST_NOROOM
        elif op == OP_LEAVE:
            self.hub.leave(self)
            self.room = None
            self.status = ST_IDLE
        elif self.room is not None and self.room not in self.hub.waiting():
            self.room = None                 # (closed by the hub)
            self.status = ST_IDLE
        if self.room is not None:
            self.status = ST_WAITING
        room = (self.room or "").encode("ascii").ljust(4, b"\0")
        return bytes([T_STATE, seq, self.status]) + room

    def _start(self, seq: int) -> bytes:
        return bytes([T_START, seq, self.sid, self.player, self.delay, 0, 0])

    def ticks(self, sid: int, seq: int, ack: int, first: int, data: bytes,
              now: float) -> bytes | None:
        if sid != self.sid or sid == 0:
            return None
        if not self.in_session:
            if self.bye_reason is not None:
                return bytes([T_RBYE, self.sid, self.bye_reason, seq])
            return None
        self.confirmed = True
        # the C64's stream: append what is new, in order
        first = unwrap8(first, self.rx_have)
        k = self.rx_have - first
        if 0 <= k < len(data):
            new = data[k:]
            self.rx_have += len(new)
            self.hub.side_ticks(self, self.rx_have - len(new), bytes(new))
            if not self.in_session:          # the hub ended it (skew / gap)
                return bytes([T_RBYE, self.sid, self.bye_reason or BYE_LOST, seq])
        # its ACK of the partner's stream
        ack = unwrap8(ack, self.tx_base)
        if self.tx_base < ack <= self.tx_base + len(self.tx):
            t0 = self.sent_at.pop(ack - 1, None)
            if t0 is not None:
                sample = int((now - t0) * 1e6)
                self.rtt_us = sample if self.rtt_us is None else (self.rtt_us * 7 + sample) // 8
            for i in range(self.tx_base, ack):
                self.sent_at.pop(i, None)
            del self.tx[:ack - self.tx_base]
            self.tx_base = ack
        out = bytes(self.tx[:WINDOW])
        for i in range(self.tx_base, self.tx_base + len(out)):
            self.sent_at.setdefault(i, now)
        return (bytes([T_RTICKS, self.sid, seq, self.rx_have & 0xFF, self.tx_base & 0xFF,
                       len(out)]) + out)

    def bye(self, sid: int, reason: int, seq: int) -> bytes | None:
        if sid != self.sid or sid == 0:
            return None
        if self.in_session:
            self.in_session = False
            self.bye_reason = BYE_LOST
            r = _FROM_WIRE.get(reason, EndReason.BYE)
            slog(log, "c64_bye", side=self.name, sid=sid, reason=reason)
            self.hub.side_ended(self, r)
        return bytes([T_RBYE, sid, reason, seq])


class C64Relay:
    """Protocol engine for all C64 clients of one hub."""

    def __init__(self, hub, *, clock: Callable[[], float] = time.monotonic,
                 delay: int | None = None, host_code: str | None = None) -> None:
        self.hub = hub
        self.host_code = host_code      # every HOST gets this room code (the joiner's CONFIG
                                        # names it); None = a random code
        self.clock = clock
        self.fixed_delay = None if delay is None else max(MIN_DELAY, min(MAX_DELAY, delay))
        self.clients: dict[tuple[str, int], C64Side] = {}
        self.next_sid = 0
        self.dropped = 0

    def datagram(self, addr: tuple[str, int], data: bytes) -> bytes | None:
        now = self.clock()
        if not data:
            return None
        t = data[0]
        cl = self.clients.get(addr)
        if t == T_LOBBY:
            if len(data) < 16:
                self.dropped += 1
                return None if len(data) < 10 else bytes([T_STATE, data[9], ST_MISMATCH, 0, 0, 0, 0])
            seq, op, code = data[9], data[10], data[11:15]
            nonce = data[7] | (data[8] << 8)
            if data[1] != PROTO or data[2:6] != APP or data[6] != APP_VERSION:
                return bytes([T_STATE, seq, ST_MISMATCH, 0, 0, 0, 0])
            if cl is not None and cl.nonce != nonce:         # a new program at that address
                self._drop(cl, EndReason.BYE)
                cl = None
            if cl is None:
                if len(self.clients) >= MAX_CLIENTS:
                    return bytes([T_STATE, seq, ST_BUSY, 0, 0, 0, 0])
                cl = self.clients[addr] = C64Side(self, addr, nonce)
                slog(log, "c64_hello", side=cl.name)
            cl.last_heard = now
            cl.n_rx += 1
            cl.n_tx += 1
            if data[15]:
                cl.lobby_rtt_frames = data[15]
            if op > OP_LEAVE:
                op = OP_POLL
            return cl.lobby(seq, op, code)
        if cl is None:
            self.dropped += 1
            return None
        cl.n_rx += 1
        reply = None
        if t == T_TICKS:
            if len(data) < 6 or data[5] > WINDOW or len(data) < 6 + data[5]:
                self.dropped += 1
                return None
            cl.last_heard = now
            reply = cl.ticks(data[1], data[2], data[3], data[4], data[6:6 + data[5]], now)
        elif t == T_BYE and len(data) >= 4:
            cl.last_heard = now
            reply = cl.bye(data[1], data[2], data[3])
        else:
            self.dropped += 1
        if reply is not None:
            cl.n_tx += 1
        return reply

    def _drop(self, cl: C64Side, reason: str) -> None:
        cl._end_here(reason)
        self.hub.leave(cl)
        self.clients.pop(cl.addr, None)
        slog(log, "c64_gone", side=cl.name, reason=reason)

    def expire(self) -> None:
        now = self.clock()
        for cl in list(self.clients.values()):
            limit = SESSION_TIMEOUT if cl.in_session else LOBBY_TIMEOUT
            if now - cl.last_heard > limit:
                self._drop(cl, EndReason.TIMEOUT)


# ---- asyncio endpoint ------------------------------------------------------------------------
class _Proto(asyncio.DatagramProtocol):
    def __init__(self, server: C64Server) -> None:
        self.server = server

    def connection_made(self, transport) -> None:
        self.server.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        em = self.server.netem
        if em is None or not em.active:
            self._handle(data, addr)
        else:
            em.schedule(asyncio.get_running_loop(), "in", lambda: self._handle(data, addr))

    def _handle(self, data: bytes, addr) -> None:
        try:
            reply = self.server.relay.datagram((addr[0], addr[1]), data)
        except Exception:  # pragma: no cover - never let one datagram stop the relay
            log.exception("c64 datagram failed")
            return
        if reply is None:
            return
        em = self.server.netem
        if em is None or not em.active:
            self._send(reply, addr)
        else:
            em.schedule(asyncio.get_running_loop(), "out", lambda: self._send(reply, addr))

    def _send(self, reply: bytes, addr) -> None:
        if self.server.transport is not None and not self.server.transport.is_closing():
            self.server.transport.sendto(reply, addr)


@dataclass
class C64Server:
    relay: C64Relay | None = None
    transport: asyncio.DatagramTransport | None = None
    netem: Netem | None = None   # simulated WAN on this leg (netem.py)
    _task: asyncio.Task | None = None

    @property
    def address(self):
        return self.transport.get_extra_info("sockname") if self.transport else None

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            self.relay.expire()

    def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
        if self.transport is not None:
            self.transport.close()


async def start_c64_endpoint(hub, host: str, port: int = DEFAULT_PORT, *,
                             delay: int | None = None,
                             netem: Netem | None = None,
                             host_code: str | None = None) -> C64Server:
    """Serve the C64 protocol on host:port. ``delay``: fixed C64 input delay (1..24), None =
    auto. ``netem``: simulated WAN on each C64's leg."""
    loop = asyncio.get_running_loop()
    server = C64Server(relay=C64Relay(hub, delay=delay, host_code=host_code), netem=netem)
    await loop.create_datagram_endpoint(lambda: _Proto(server), local_addr=(host, port))
    server._task = loop.create_task(server._expire_loop())
    a = server.address
    slog(log, "c64_listening", address=f"{a[0]}:{a[1]}",
         delay=delay if delay is not None else "auto",
         wan=netem.describe() if netem is not None and netem.active else "off")
    return server
