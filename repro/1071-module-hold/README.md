# Bench-only WiFi module hold, for repeating the hold test of PR #1071

This is not for merging. It adds one bench command that makes the ESP32 WiFi module stop reading its UART, so the
module's hardware RTS stalls the Ultimate's WiFi UART transmit while the WiFi link stays up. That is the condition the
PR's red/green test needs: the host's TX buffers run out, and the old `wifi_tx_packet` then waits for a buffer under the
lwIP core lock while Ethernet and REST freeze.

## What is in it

Commits on top of `upstream/master`, nothing else:

1. **Module** (`software/wifi/raw_u64`, `software/wifi/raw_c3`, `software/u64ctrl`; files `my_uart.c/.h`,
   `rpc_calls.h`, `rpc_dispatch.c`). New module command `CMD_BENCH_HOLD_RX` (0xB1): request = RPC header + `u32 ms`,
   reply = RPC header + `esp_err` + `u32 held_ms`. `ms` is clamped to 1..10000, 0 releases. The module queues the reply,
   then masks the UART RX interrupts. The FIFO fills and RTS holds the Ultimate's TX; the module's own TX, the radio, air
   frames and events go on. A one-shot timer ends the hold on its own, a release or a second hold re-arms it, a module
   reset clears it. While held, neither the end of the RX interrupt nor `my_uart_free_buffer()` re-enables RX. Two
   diagnostic events (0xB2 command seen, 0xB3 reply left the UART) are sent as well; the Ultimate logs them as unexpected
   events, which is harmless.
2. **Host** (`software/io/wifi/wifi_cmd.cc`, `wifi_bench_hold.h`, `bench_hold_ctrl.h`, `software/io/network/network_target.cc/.h`).
   UCI network-target command `0xE5`, built only for the targets that build `wifi_cmd.cc` (U64/U64E Nios, Ultimate 64
   Elite II and C64 Ultimate RISC-V, U2+/U2+L). Frame: `03 E5 <ms u32 little endian>`. The reply is 8 data bytes
   (`esp_err` i32 LE, `held_ms` u32 LE) with status `00,OK`. The host waits for the module's reply only (at most the
   clamped hold plus 1 s), never for the hold itself, so the UCI task is not parked for the hold. Other statuses:
   `99,HOLD NOT SUPPORTED` (module without the command, i.e. not the hold module), `98,NO WIFI UART`, `98,NO TX BUFFER`,
   `98,NO REPLY SLOT`, `98,BAD WIFI REPLY`, `81,INVALID PARAMS`, `01,HOLD SENT NO REPLY` (sent, no answer in time).
3. **Module version**: `IDENT_MINOR` is raised by 100 in the three modules (see "Flashing the module").
4. Comment clean-up.

Host tests: `software/io/network/tests/bench_hold.mk` (15 cases, 19 models that must fail) and
`target/pc/linux/wifireply` (`make test`, `make bench-hold-red`). The first is a separate make file on purpose, so no
existing Makefile is touched and nothing here conflicts with the PR's Makefile changes.

```
make -C software/io/network/tests -f Makefile -f bench_hold.mk bench-hold bench-hold-red
make -C target/pc/linux/wifireply test
make -C target/pc/linux/wifireply bench-hold-red
```

## Applying it

On master:

```
git fetch <this repo> repro/1071-module-hold
git checkout -b hold-master upstream/master
git cherry-pick <first commit of the branch>^..<last commit of the branch>
```

On the head of PR #1071 (`fix/wifi-tx-nowait`): the same cherry-pick on a branch made from the PR head. No conflicts
on `b9cdfe261` (the merge of master into the PR) or on master `085aad730`.

Red and green need the same hold build on both sides: build RED from master plus this branch, GREEN from the PR head
plus this branch. Then only the TX path differs between the two images.

## Building and flashing the module

The module change is in the three module projects, each built the usual way with its own ESP-IDF project
(`software/wifi/raw_u64`, `software/wifi/raw_c3`, `software/u64ctrl`). The firmware update image carries the module.

The updater reflashes a module only when the image's version differs from the module's (U64/U64E) or is higher (C64
Ultimate, Ultimate 64 Elite II, U2+L). The module change alone would be skipped. For that, the branch raises
`IDENT_MINOR` by 100 in all three modules, above any stock module. Consequences:

- On the Ultimate 64 Elite (`!=` rule) a later stock image replaces the hold module by itself.
- On the C64 Ultimate and the U2+L (upgrade-only) a later stock image will say the module is newer and keep it.
  To go back to the stock module, build one update image with the module version check forced (change the version
  comparison in the updater's ESP32 step to always flash), or lower the version of your hold build below the stock one
  and force-flash the first time. A hold module left on a device is otherwise harmless: it answers only `0xB1`.
- Check with the UCI command: on a stock module `03 E5 00 00 00 00` answers `99,HOLD NOT SUPPORTED`, on the hold
  module it answers `00,OK` and 8 data bytes.

## Driving the hold

Settings of the recorded runs: Ethernet and WiFi both connected; a host pings the device over Ethernet every 100 ms and
polls REST in a loop; another host sends 300 UDP packets per second to the device's WiFi address, so the host's WiFi TX
path stays busy; then three holds of 3000 ms, 30 s apart.

1. Send `03 E5 b8 0b 00 00` (3000 ms) on the UCI network target. The answer is `00,OK` with data `00 00 00 00 b8 0b 00 00`
   at once. The hold runs on the module and ends by itself.
2. During the hold read the largest gap between Ethernet ping replies, the ping loss, and the largest REST latency.
3. Between holds wait for the module to recover (WiFi ping answers again).

## What to expect

RED is master's waiting `wifi_tx_packet`, GREEN is the PR. Recorded in the PR description (three holds each, 3000 ms):

| | Elite RED | Elite GREEN | Elite, PR head | C64 Ultimate RED | C64 Ultimate GREEN |
|---|---|---|---|---|---|
| Ethernet ping, max gap | 2974 / 2961 / 2957 ms | 105.6 / 105.2 / 105.5 ms | 111.2 / 110.5 / 113.9 ms | 2906 / 2916 / 2955 ms | 110 / 110 / 110 ms |
| Ethernet ping loss | 66.7 % | 0 % | 0 % | 63 / 66 / 64 % | 0 % |
| REST, max latency | 3013 / 5177 / 2848 ms | 49 / 32 / 61 ms | 22 / 49 / 23 ms | 2746 / 2906 / 2896 ms | 36 / 25 / 36 ms |

RED means the whole stack stops for about the length of the hold (gap close to 3 s, two thirds of the pings lost). GREEN
means the gap stays at the 100 ms ping interval plus jitter, no loss, REST in tens of milliseconds. Baseline before the
holds is about 110 ms gap and 20 ms REST. The head has no counters, so on the head the hold is confirmed by the
module's `00,OK` only.

The recorded Elite runs used the hold module from the earlier bench images; this branch is a port of that code to the
current master, built to compile for the three module projects but not yet run on a device by us.
