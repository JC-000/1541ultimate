# UCI lockstep benchmark

Two C64s play one lockstep session over the network, each through its Ultimate's Command
Interface (UCI). This kit measures how often they stall, and what each frame costs the 6502.
It compares firmware builds on the one thing that differs between them: what `SOCKET_READ`
($10) does when the socket is empty.

- **The READ waits.** On the current firmware an empty READ blocks for up to 40 ms
  (`SO_RCVTIMEO`), about 37 ms measured, then answers `$FFFF`, `02,NO DATA`. The interface takes
  no other command meanwhile.
- **The READ answers at once.** On a build with `MSG_DONTWAIT`, an empty READ answers `$FFFF`,
  `02,NO DATA` in about a millisecond.

A lockstep game sends one datagram a frame each way. At 60 Hz a frame is 16.7 ms, so a READ
that waits 37 ms costs more than two frames. During the wait the game cannot send its own
datagram either.

This is a benchmark: it prints numbers, it does not pass or fail. It is not registered in
`run-tests`.

## What you need

- Two Ultimates with the UCI (Ultimate 64, Ultimate 64 Elite, C64 Ultimate), both running the
  firmware you want to measure.
- On both: **Command Interface** set to Enabled (C64 and Cartridge Settings), Turbo Control off,
  and System Mode NTSC. The client is timed for a 1 MHz NTSC C64. `--enable-uci` sets the
  Command Interface for you.
- A PC on the same LAN with Python 3.12 or newer. It runs the relay, so both devices must reach
  it on UDP port 6520.
- Wired Ethernet on both devices gives the cleanest numbers.
- To rebuild the client: cc65 (`ca65`, `ld65`) and `make`. The prebuilt `client/lockstep.prg`
  is enough to run.

## Running

One run, on the LAN with 1% loss on each leg, for three minutes:

```sh
tests/perf/uci_lockstep/run_pair.py --host-a 192.0.2.10 --host-b 192.0.2.11 \
    --wan-loss 0.01 --delay 2 --seconds 180
```

All six paths, one after the other (about 20 minutes):

```sh
tests/perf/uci_lockstep/run_pair.py --host-a 192.0.2.10 --host-b 192.0.2.11 \
    --matrix --label current-firmware
```

Run it once per firmware build, with the same devices and the same paths, and compare the two
`summary.md` files. The relay seeds its loss and jitter the same way every time (`--wan-seed`).

| Path (`--only` name) | Each C64's leg to the relay | Input delay |
|---|---|---|
| `lan` | LAN | 2 |
| `lan-loss` | LAN, 1% loss each way | 2 |
| `wan5` | 17.5 ms ±2.5 each way, so 35 ms between the C64s | 5 |
| `wan5-loss` | the same, 1% loss | 5 |
| `wan10` | 17.5 ms ±5 each way | 5 |
| `wan10-loss` | the same, 1% loss | 5 |

Device A hosts a room, and device B joins it. `run_pair.py` starts each device's program over
REST (`runners:run_prg`), reads its status block every second (`machine:readmem`), and stops it
at the end (`machine:writemem`). It writes everything to `results/<label>/`: one `result.json`
per path, the relay's log and summary, and `summary.md`.

## What the columns mean

- **Stalls/min**: frames in which a C64 had the other's input byte too late and could not run
  its tick. This is what a player sees as stutter.
- **Ticks/s**: session ticks per second. Without stalls it is 60.
- **Empty READs**: READs that came back with no datagram.
- **Late/lost**: replies the client took a frame late, and replies that never came. These are
  8-bit counters, so they wrap.
- **Errors**: UCI errors on either C64. It should be 0.
- **Worst frame**: the most CPU cycles any one frame took, network and the client's own work
  together. A frame has 17 095 cycles (NTSC).
- **Digests equal/different**: every 256 ticks both C64s send a checksum of their state, and the
  relay compares the two. Any "different" means the two machines fell out of step.

## How the client reads

The client checks at run time whether an empty READ answers at once: it looks at how many polls
an empty READ held the interface. Then it reads one of two ways.

- **When the READ waits**, the client READs once a frame, after its own frame work. By the next
  frame the reply has usually arrived, and the READ finds it.
- **When the READ answers at once**, reading once a frame is not enough. A reply that lands just
  after that READ would wait a whole frame. So the client does two things:
  - It READs again at the start of each frame.
  - While a reply is overdue, it READs once more just before it pushes the frame's WRITE. It
    stops after 40 raster lines (about 2 600 cycles), or after one empty READ, whichever comes
    first.

Without the raster-line limit, that second READ can poll a busy interface for most of a frame.

`client/session.s` (`poll_mid`) and `client/uci.s` hold the details. `client/net.inc` describes
the driver interface.

## The wire protocol

UDP, relay port 6520, little-endian. The relay answers every datagram exactly once and never
sends on its own.

| Type | From | Layout |
|---|---|---|
| `$01` LOBBY | C64 | `$01 PROTO=3 "LS64" VERSION=1 NONCE(2) SEQ OP CODE[4] RTT` |
| `$10` TICKS | C64 | `$10 SID SEQ ACK FIRST N BYTES[N]`, N ≤ 6 |
| `$1F` BYE | C64 | `$1F SID REASON SEQ` |
| `$81` STATE | relay | `$81 SEQ STATUS ROOM[4]` |
| `$82` START | relay | `$82 SEQ SID PLAYER DELAY 0 0` |
| `$90` TICKS | relay | `$90 SID SEQ ACK FIRST N BYTES[N]` |
| `$9F` BYE | relay | `$9F SID REASON SEQ` |

- `OP` is 0 to poll, 1 to host a room, 2 to join `CODE`, and 3 to leave.
- Every datagram from the C64 carries a new `SEQ`, and the reply echoes it. So the C64 knows how
  many replies it is owed.
- `TICKS` carries the input bytes the other side has not yet acknowledged, plus an `ACK` of what
  it received.
- Every tick whose number ends in `$FF` carries a state digest instead of an input byte.

## Files

| Path | What it is |
|---|---|
| `run_pair.py` | Runs one path or all six on two devices and prints the table |
| `relay/` | The relay: rooms, tick forwarding, digest comparison, simulated delay, jitter and loss |
| `client/` | The 6502 client (ca65), its `Makefile`, and the prebuilt `lockstep.prg` |

`make -C tests/perf/uci_lockstep/client check` rebuilds the PRG and compares it with the
committed one.
