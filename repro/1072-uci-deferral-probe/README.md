# Hardware probe for #1072 (UCI deferral)

This is the probe we used for the hardware table in the PR description. It needs only an Ultimate on the network and a
PC on the same network. It loads and flashes nothing: put the firmware under test on the device first (flash, or a
JTAG RAM load on the C64 Ultimate), then run the probe.

## What it does

A small HTTP server on the PC accepts the connection of a UCI HTTP exchange (target 6, `DO_EXCHANGE_RAW`, handle from
`HEADER_CREATE` on a GET to that server) and never answers. A 6502 routine on the C64 pushes the exchange and times what
follows with CIA2 timers (1 ms ticks, NTSC). The next program's first command is `IDENTIFY` on target 4, pushed with no
abort preamble in front of it, the way a program that has just started would do it. The PC drives the C64 through the
Ultimate's REST API (memory read/write, key injection, reset).

| Leg | What happens | RED (master) | GREEN (PR) |
|---|---|---|---|
| `abort` | exchange stalls 2 s, the C64 writes ABORT, the routine times ABORT until state 00 (the abort bit is gone). Then IDENTIFY. | abort takes the rest of the 30 s receive timeout; the stub sees the device close the socket after about 28 s | abort under 50 ms; the stub sees the device close the socket within 300 ms; IDENTIFY answers on the first try |
| `reset` | exchange stalls, the C64 program returns to BASIC, after 2 s the PC resets the C64; at READY the probe reads the status byte, then pushes IDENTIFY | status after reset is 11 (BUSY), the push sets ERROR (busy), the probe waits about 25 s for idle and pushes again (`tries` 2) | status after reset is idle, the first push works (`tries` 1), reply in under 50 ms |
| `late` | the stub answers 4 s after the request; the C64 aborts after 1 s; 2 s after the late answer the probe runs | abort takes about 3000 ms (it waits for the answer) | abort under 50 ms; the stub never gets to send its answer; the probe finds the interface idle (no unsolicited state 10 from a late result) and IDENTIFY works |

The `late` leg's second check (a late result must not show up as a new reply) cannot fail on master, only the timing can.
Exit code is 0 only if every leg is GREEN; each leg prints a JSON record and appends it to `probe_1072.jsonl`.

## Numbers from our runs (2026-11-11)

RED is `82997689a`, the merge base of the PR heads (master at the time), and GREEN is the PR head `0c0b1dad9`. All runs
were on core 1.50. We have not run `6f89946bf` or any later master.

| | Ultimate 64 Elite RED | C64 Ultimate RED | both GREEN (`0c0b1dad9`) |
|---|---|---|---|
| abort: ABORT to idle | 27965 ms | 27978 ms | 0 ms (below the 1 ms tick) |
| abort: device closes socket after ABORT | 27980 ms | 27993 ms | 84 to 91 ms |
| reset: first IDENTIFY, status at READY / tries / time | `11` / 2 / 24754 ms | `11` / 2 / 24757 ms | `00` / 1 / 0 ms |
| reset: device closes socket after reset | 27933 ms | 27940 ms | 34 to 41 ms |
| late: ABORT to idle | 3019 ms | 3024 ms | 0 ms |
| late: stub's answer sent before the device closed | yes | yes | no |

IDENTIFY answered `CONTROL TARGET V1.1` in every run. On GREEN the U64E legs were run twice with the same result.
The RED figure of about 28 s is the remainder of the 30 s receive timeout on master after the 2 s stall. On a build
with no receive timeout at all, the abort leg hits the routine's 60 s cap instead (`abort_timed_out` true).

## Setup

You need Python 3.10 or later and the c64-test-harness, which provides the REST client, memory access and key injection:

    git clone https://github.com/JC-000/c64-test-harness
    cd c64-test-harness && pip install -e .

Check the probe without a device (assembles the routines, runs the stub server against a local client):

    python3 probe_1072.py selftest

Run it, with the device sitting at BASIC READY and nothing else using it:

    python3 probe_1072.py run --host <device-ip> --expect-git <short hash of the firmware you loaded>

Options: `--legs abort,reset,late` (default all three, in that order), `--out FILE`, `--no-config`, `--no-lock`.
Run it once on master and once on the PR to get RED and GREEN.

Before the legs it sets, at runtime and without saving, CPU Speed 1, Turbo Control Off, System Mode NTSC and Command
Interface Enabled, reads each back, and records them in the JSON. `--no-config` skips that if you have set up the device
yourself; the routines assume NTSC timing for the millisecond figures, and the Command Interface must be enabled.
The C64 is reset at the end so no routine is left running.

The PC must be reachable from the device on a TCP port it picks itself (the stub listens on an ephemeral port on all
interfaces), so a firewall on the PC may need to allow it.

## Per product

- **Ultimate 64 Elite**: load the firmware (flash, or volatile if you have a way), wait for REST, run.
- **C64 Ultimate**: same. We loaded the images into RAM over JTAG; the probe does not care how the image got there.
  Run it right after the load and reset, and pass `--expect-git` so a stale image is caught.
- **U2+L**: the probe uses only REST and the UCI, so it should work unchanged once the device is on the network. We have
  not run it on a U2+L. System Mode and CPU Speed are U64 settings; if the U2+L has no such item the config step fails
  with a message, and `--no-config` skips it (then set the Command Interface by hand).

## What needs our setup

Nothing else is required beyond the c64-test-harness. The harness is also what takes a cross-process lock on the device
for the length of the run (`--no-lock` turns that off). We kept all device access of ours behind it, so we have not run
a version of the probe written against raw REST calls.

## Files

- `probe_1072.py`: the driver, the 6502 routines (generated from Python, with the assembly described in the docstrings
  of `build_push_only`, `build_push_then_abort`, `build_probe`, `build_settle`) and the stub server.
- `prebuilt/*.prg`, `*.hex`: the four routines as assembled by `probe_1072.py dump DIR`. Each loads at `$2000` and is run
  with `SYS 8192`. They use `$C0BF-$C0FF` and `$C100-$C11F` for parameters and results, and CIA2 timers A and B.
  The program assumes it is the only thing using the UCI while it runs.
