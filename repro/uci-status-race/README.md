# UCI $DF1C status race: reproduction kit

A 6510 program polling the Command Interface control register ($DF1C) can read state **11** (Data More) on the block
that is really the last of a reply. The register never holds 11 at that point. A client that believes the first
sample sends DATA_ACC, the interface goes idle, and the client waits for a block that will never come.

## What happens (inferred from the RTL, not observed in the FPGA)

`slot_status` is one register on the slot-server clock. VALIDATE on the last block changes both state bits in one
clock (01 to 10, [command_protocol.vhd:220-226](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/io/command_interface/vhdl_source/command_protocol.vhd#L220-L226)).
The C64 read is a combinational mux on that live register
([:97-103](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/io/command_interface/vhdl_source/command_protocol.vhd#L97-L103),
[slot_server_v4.vhd:1044-1045](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/cart_slot/vhdl_source/slot_server_v4.vhd#L1044-L1045),
[slot_slave.vhd:293-295](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/cart_slot/vhdl_source/slot_slave.vhd#L293-L295),
[slot_server_v4.vhd:1071-1073](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/cart_slot/vhdl_source/slot_server_v4.vhd#L1071-L1073)). Nothing holds the value for the
duration of the read, so if the C64 side captures the byte at the clock edge where the register changes, each of the two
state bits can resolve to its old or new value on its own: 10 can read as 11 or 00. Single-bit transitions cannot be misread
this way.

A second, separate effect: bits 7 and 6 (data available, status available) are registered one FPGA clock after the state
changes ([:128-137](https://github.com/GideonZ/1541ultimate/blob/4ac0608ee2c679b0fba353e76ee984531983bb17/fpga/io/command_interface/vhdl_source/command_protocol.vhd#L128-L137) against :219-225). So for one clock a
perfectly clean read can show state 1x with DATA_AV and STAT_AV still 0. This is inferred from the RTL; the probe counts it
separately (LAG) but we have not yet looked at its rate.

## Workaround for clients

Do not act on the first sample that shows state 1x. Re-read until two consecutive reads agree on bits 7-4 (mask $F0:
DATA_AV, STAT_AV and the two state bits) and decide on that. Discarding one read is not enough, because the lag and the torn
read can both show up on the read after it. `probe-recheck.prg` does exactly this in `wait_reply`.

## What we measured, and what is inferred

Measured on one machine: U64 Elite, core 1.50, FPGA 126, firmware 3.15a built from master 4ac0608ee plus unrelated changes;
CPU Turbo Manual 48 MHz, NTSC; Command Interface enabled; replies from a host on the LAN.

- A benchmark PRG that also does TLS reads, patched (an earlier variant than the probe here: it re-read $DF1C three times when
  a block that must be the last said 11, and treated it as last when the first re-read said 10). Series
  of 40 runs (each run: one 256 KiB TLS transfer and one plain-TCP transfer, 484 READ commands in all), 13 series: about
  251,700 last blocks, 8 events, 3 of them in the plain-TCP leg. Rate 3.2e-5 per last block (Poisson 95% interval
  1.4e-5 to 6.3e-5), which is about 1.5% of runs. Later series gave more events (15 in 18 series, 5 plain).
- Every event: first sample $32 (5 times) or $30 (3 times); all 24 re-reads $20. With "treat as last when the re-read says
  10", all 520 runs completed. $32 is $22 with bit 4 already set; $30 is $20 likewise: bit 5 new, every other bit old.
- Unpatched, a run hung once. Halted before reset: both blocks drained, all bytes correct, $DF1C = $00, $DF1D = $C9.
- The probe cannot see the 00 misread, so the true total is probably higher. 1 MHz, U2/U2+ and C64U are not measured.
  That the same race exists there, and about ten times less often at 1 MHz, is a prediction.
- TLS plays no part. Any multi-block READ has the 01 to 10 edge; this kit uses plain TCP only.

## Setup

- A U64 / U64E (or any machine with the Command Interface) with the network up. Set **CPU Speed to Turbo Manual 48 MHz**
  and **Command Interface Enabled** in the menu. At 1 MHz we expect far fewer events; running both is a useful comparison.
- A host on the same LAN. Use an address the device can reach; below `192.0.2.10` is a placeholder.

## Run

1. On the host, start the sender (stdlib only; the size must match the PRG's):

       python3 host/sender.py --port 18444 --size 262144

2. Put the host's address and the run length into a PRG. Two prebuilt PRGs are in `prebuilt/` (sha256 below):
   `probe-recheck.prg` logs a misread and carries on; `probe-hang.prg` counts it and then believes it like an ordinary
   client, so the run ends with ERR 11 (timeout waiting for a reply).
   Both count the same things from the first sample; `recheck` additionally confirms the sample it acts on with two
   agreeing reads of $F0.

       python3 host/mkcfg.py prebuilt/probe-recheck.prg probe.prg --host 192.0.2.10 --port 18444 --size 262144 --conns 40
       python3 host/mkcfg.py prebuilt/probe-hang.prg probe-hang.prg --host 192.0.2.10 --conns 40

3. Load the PRG and RUN it by any means you have: copy it to the device's drive and start it from the menu, send it with
   the REST API's `runners:run_prg`, or any other loader. Nothing needs to be written to the C64 afterwards. (We used the
   c64-test-harness; that is optional.) The program runs with interrupts off and finishes on its own after `--conns`
   connections (one connection is one OPEN, a one-byte WRITE, about 178 READs of 1472 bytes, one CLOSE). Use `--conns 0` to run until you stop the machine.
4. Read the result. The program prints it on the screen when it ends:

       DONE=5A ERR=00
       CONNS=0028
       READS=001BF8
       LAST BLOCKS=001C70
       RACE EVENTS=0001
       ACTED=0001 STILL=0000
       LAG (BITS 7/6)=0000
       DIS=0001 MISM=0000

   or dump the 192 bytes at $C000 with any tool and run `python3 host/decode.py dump.bin` (or `decode.py --device HOST`,
   which does one read-only GET of `machine:readmem`).

## How to read the table

| field | meaning |
|---|---|
| DONE | $5A finished, $EE stopped on an error, $00 still running |
| ERR | 11 = timed out waiting for a reply (the hang), 5 = READ failed, 2/4/7 = OPEN/WRITE/CLOSE failed |
| READS, LAST BLOCKS | READ commands issued; blocks that were the last of their reply (shorter than 895 bytes, which includes the replies to OPEN, WRITE and CLOSE) |
| RACE EVENTS | last blocks whose first sample said 11. This is the race |
| ACTED | events where the first re-read said 10 (the register never held 11). STILL = re-read said 11 again: not the race, report it |
| LAG | blocks whose first sample had DATA_AV and STAT_AV both clear although the block carried bytes: the one-clock lag of bits 7/6. Counted separately from the race |
| DIS | blocks whose first sample differs from a read after the drain, in any state. Any state change between the two samples counts, not only the race, so DIS is at least RACE EVENTS |
| MISM | payload bytes that differ from their stream offset (the sender sends byte i = i & 255). Should be 0 |

The log of the first 16 events (sample, three re-reads, bytes in the block, READ number) is at $C040, 8 bytes each;
`decode.py` prints it. Expect first samples of $30 or $32 and re-reads of $20.

Unpatched, the expected rate is about one hang per 1/3.2e-5 last blocks, about 1.5% of 256 KiB runs in our setup. With
`probe-recheck.prg` the same events are logged and the run completes. A few thousand READs with no event proves nothing;
we needed on the order of 250,000 last blocks (about 13 series of 40 runs) to see 8.

## How the probe decides

A "more" block always holds 895 data bytes (893 plus the 2-byte header in the first block of a READ), so after a block is
drained, a block shorter than that must be the last of its reply. If the sample that ended the wait for it said 11, that is
a misread. The probe then reads $DF1C three times and counts and logs the event. In the recheck build the sample the
client acts on was already confirmed by two agreeing reads of $F0, so the block is taken as last. The wait sample and the decision sample are the same read, which is exactly what a client that decides
more/last from the first "reply ready" sample does.

## Build and test

    64tass -a -D ACT=1 probe.asm -o prebuilt/probe-recheck.prg
    64tass -a -D ACT=0 probe.asm -o prebuilt/probe-hang.prg
    python3 selftest.py            # or: python3 selftest.py --build

`selftest.py` runs the PRGs in a small 6502 simulator against a mock Command Interface that can be told to read 11 on the
first sample of a last block. It checks the bookkeeping, the byte check and the two build variants and an injected one-read lag of bits 7/6. It tests the PRG, not
the hardware, and does not show that the race exists.

## Files

- `probe.asm`: the 6510 probe (config block at $0810 inside the PRG, results at $C000).
- `prebuilt/`: `probe-recheck.prg`, `probe-hang.prg`, `SHA256SUMS`.
- `host/sender.py`, `host/mkcfg.py`, `host/decode.py`: stdlib only.
- `selftest.py`, `tools/sim6502.py`: offline check.

Written with Claude Sonnet 5.5 in Claude Code.
