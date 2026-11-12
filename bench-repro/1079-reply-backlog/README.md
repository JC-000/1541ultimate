# Bench repro for #1079: the module's reply backlog, and a burst to measure it

Bench only, never for upstream. This branch is `master` plus one commit that adds a backlog counter to the module's UART
TX path and a command that reads it, so that "master + #1078" (before) and "master + #1078 + #1079" (after) can be
compared on hardware. It contains neither PR. It goes on top of either: it applies to `upstream/master`, to the #1078
head (`49074a0d2`) and to the #1079 head (`8e9182b61`) with `git apply --check`, and it touches none of the lines the two
PRs change.

## What it counts

In the module, `my_uart_transmit_packet()` (every reply and event goes through it) notes, before it queues a frame, how
many frames are already waiting in the UART transmit queue:

- `q_max`: the most frames queued for the UART at once (the one being queued included) since the counters were cleared.
  This is the "11 replies queued" number, read on the module.
- `frames`: frames handed to the UART since the counters were cleared.
- `left`: frames in the queue right now (read at the time of the command).

## The command

Module command `CMD_BENCH_TXQ` (0x6C), request `{hdr; u32 arg}`, reply `{hdr; int esp_err; u32 sent; u32 q_max; u32
left; u32 drain_us; u32 frames}`. `arg` = `burst | size << 16 | 0x80000000 (reset)`:

- `burst` = 0 and no reset flag: read only. `left` is the backlog now, `q_max` and `frames` are what was counted since the
  last clear (after a reset or a burst; before that, since the module booted).
- reset flag: clears `q_max` and `frames`.
- `burst` > 0 (clears the counters first): the module queues `burst` events (code 0x6F, thread 0xFF, `size` bytes, 4..1500,
  0 = 4) back to back, as fast as it can, then waits at most 200 ms for the UART to be idle (queue empty, no frame in the
  ISR, TX FIFO idle) and reports. `sent` is how many it could queue (it stops when no TX buffer is free: at most 11 or 12);
  `left` is what was still queued when the wait ended (before the reply is queued); `drain_us` is the time from the first
  frame queued to the UART idle (200000 when frames are left).

The reply is queued after that, so it carries the state before the reply's own kick.

Host side (all products with a WiFi module): UCI network target (target 3) command `0xE7`, 6 bytes `03 E7 <arg u32 little
endian>`. Data of the reply: the module's reply body, 24 bytes (esp_err, then the five u32 above). Status `00,OK`;
`86,INTERNAL ERROR` when the module did not answer within 2 s; `81,INVALID PARAMS` for another length; `unknown command`
on a product without a WiFi module. The call blocks the UCI for the round trip (bench only). Needs "Command Interface"
enabled. The Ultimate prints each burst frame on its console as `Unexpected Event type: Pkt n. Ev 6F. Sz <size>. Seq: i.
Thread: 255.`, which counts the frames that arrived.

Files: `software/{wifi/raw_u64,wifi/raw_c3,u64ctrl}/main/{my_uart.c,my_uart.h,rpc_dispatch.c}` (the same text in all
three), `software/io/wifi/wifi_cmd.{cc,h}` (`wifi_bench_rpc`), `software/io/network/network_target.cc` (CRLF kept).

## Apply

```
git checkout -b before <head of #1078>       # BEFORE: master + #1078 (+ this)
git cherry-pick <this commit>

git checkout -b after <head of #1079>        # AFTER:  master + #1078 + #1079 (+ this)
git cherry-pick <this commit>
```

**Module version.** The Ultimate's updater only installs a module whose version differs from the one the module reports.
Bump `IDENT_MINOR` and `IDENT_STRING` in `rpc_dispatch.h` of each module you flash (raw_u64 for the Elite, raw_c3 for the
U2+L), or the new module is silently not installed. Use the same bump on both builds, and flash the module in both cases.
The patch does not touch the version.

## Drive it

(UCI, as in `tests/e2e/io/command_interface/net_target_test.py`; sketch, not run against a device.)

```python
def txq(burst=0, size=0, reset=False):
    arg = burst | (size << 16) | (0x80000000 if reset else 0)
    d = uci.transact(bytes([TARGET_NETWORK, 0xE7]) + struct.pack("<I", arg)).data
    return dict(zip(("esp_err", "sent", "q_max", "left", "drain_us", "frames"), struct.unpack("<iIIIII", d)))
```

1. The burst. Device idle, WiFi up. `txq(burst=11)` (4 byte frames), then `txq()` after a second.
   - If the TX interrupt does not start a frame that was queued while the FIFO was already below its threshold (the
     behaviour #1079 describes, seen on a C64 Ultimate), master + #1078 shows `left` = 10 and `drain_us` = 200000, and the
     console shows fewer than 11 `Ev 6F` lines at first: the rest come out one per later frame. That is what the host
     model in #1079 predicts (11 queued, 10 left).
   - On master + #1078 + #1079 expect `left` = 0, `drain_us` small, 11 `Ev 6F` lines at once.
   - If master + #1078 also shows `left` = 0 on your device, the stall does not occur on that chip: say so, it is a result.
     The #1079 text says the edge-like behaviour was seen on the C64 Ultimate and that the IDF headers document a level
     behaviour; this is the measurement that settles it per product. `q_max` = 11 in both cases (it counts the queue, not
     the sending).
2. Throughput. `txq(burst=11, size=1000)`, several times, and compare `drain_us` before and after:
   bytes/s = `sent * size * 1e6 / drain_us`. The UART limit is the baud rate / 10: 6666667 baud on the Elite and the
   C64 Ultimate (about 667 KB/s), 5000000 on the U2+L (500 KB/s). The Ultimate's CTS can slow it: it prints each event
   and has a limited number of receive buffers. Compare the two builds on the same setup, not with the limit.
3. Backlog under real traffic. `txq(reset=True)`, run your workload (replies and events at your usual rate; ping or HTTP
   through WiFi, or repeated scans), then `txq()`: `q_max` is the worst backlog the module met, `frames` how many frames it
   sent. Note that the burst clears the counters, so read `q_max` before you run a burst.

## Our recorded numbers

There is no number from this counter: it is new. What we have:

- The "11 queued" was read on the host, on a C64 Ultimate with a diagnostic build: a constant reply lag of 11, one reply
  released per request, and 11 old-application replies that came out after an application reload. It was not a module
  counter.
- Host model (`software/wifi/uart_tests`, `isr_tx_test.cpp`): a burst of 11 replies leaves 10 queued on the code without
  #1079 and sends all with it. A model, fitted to that evidence; not measured on a chip.
- Hardware, C64 Ultimate: with the TX fill, a bench request that got no reply before (`HOLD SENT NO REPLY`) was answered
  (`00,OK`) after it. The PR descriptions give the Elite and C64 Ultimate rows for the firmware they ran.
- No throughput figure, before or after, on any product. Not run on the U2+L or the Elite.

## What this patch cannot give you

- A reading of how often the stall happens in normal use before the burst: `q_max` over real traffic is the closest
  (step 3), and it is unmeasured.
- A per-frame timestamp: `drain_us` is a total, and the host's `Ev 6F` lines carry no time.
- A way to run both PRs' behaviour on one module: it is one build per column.
