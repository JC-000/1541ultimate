# Bench-only WiFi module hold, for the hold tests of PR #1071 and #1078

This is not for merging. It adds one bench command that makes the ESP32 WiFi module stop reading its UART for a set
time. It serves two tests:

- **#1071** (WiFi TX never waits): with RTS on, the module's hardware RTS stalls the Ultimate's WiFi UART transmit while
  the WiFi link stays up. That is the condition the PR's red/green test needs: the host's TX buffers run out, and the old `wifi_tx_packet` then waits for a buffer under the
lwIP core lock while Ethernet and REST freeze.
- **#1078** (RX FIFO overflow): with bit 31 of the argument set the module also switches its RTS flow control off for the
  hold, so the Ultimate keeps sending, the module's 128 byte RX FIFO overflows, and the module reports it in an event at
  the end of the hold.

One command, one branch, for both. Do not mix it with another hold command.

## What is in it

Commits on top of `upstream/master`, nothing else (plus the script and this README):

1. **Module** (`software/wifi/raw_u64`, `software/wifi/raw_c3`, `software/u64ctrl`; files `my_uart.c/.h`,
   `rpc_calls.h`, `rpc_dispatch.c`). New module command `CMD_BENCH_HOLD_RX` (0xB1): request = RPC header + `u32 ms`,
   reply = RPC header + `esp_err` + `u32 held_ms`. `ms` is clamped to 1..10000, 0 releases; bit 31 (`0x80000000`)
   switches RTS flow control off for the hold (CTS stays) and sets `sw_rts` so that the RTS pin reads "ready"; whatever
   ends the hold puts RTS back first, a new hold never inherits it. The module queues the reply,
   then masks the UART RX interrupts. The FIFO fills and RTS holds the Ultimate's TX; the module's own TX, the radio, air
   frames and events go on. A one-shot timer ends the hold on its own, a release or a second hold re-arms it, a module
   reset clears it. While held, neither the end of the RX interrupt nor `my_uart_free_buffer()` re-enables RX. When
   a hold ends (timer, release, a failed timer start) the module sends the event `0x6E` (thread 0xFF) whose sequence is
   `0x8000 | bytes in the RX FIFO`, the 0x8000 bit being the raw overflow status, read before anything can reset the FIFO.
   The Ultimate prints it as `Unexpected Event type: Pkt n. Ev 6E. Sz 4. Seq: <n>. Thread: 255.`. Two more diagnostic
   events (0xB2 command seen, 0xB3 reply left the UART) go out at the start; they are harmless. The codes used are
   0xB1, 0xB2, 0xB3 and 0x6E, and they do not collide with the reply-backlog counter bench branch (0x6C, 0x6F, UCI 0xE7).
2. **Host** (`software/io/wifi/wifi_cmd.cc`, `wifi_bench_hold.h`, `bench_hold_ctrl.h`, `software/io/network/network_target.cc/.h`).
   UCI network-target command `0xE5`, built only for the targets that build `wifi_cmd.cc` (U64/U64E Nios, Ultimate 64
   Elite II and C64 Ultimate RISC-V, U2+/U2+L). Frame: `03 E5 <ms u32 little endian>`. The reply is 8 data bytes
   (`esp_err` i32 LE, `held_ms` u32 LE) with status `00,OK`. The host waits for the module's reply only (at most the
   clamped hold plus 1 s), never for the hold itself, so the UCI task is not parked for the hold. Other statuses:
   `99,HOLD NOT SUPPORTED` (module without the command, i.e. not the hold module), `98,NO WIFI UART`, `98,NO TX BUFFER`,
   `98,NO REPLY SLOT`, `98,BAD WIFI REPLY`, `81,INVALID PARAMS`, `01,HOLD SENT NO REPLY` (sent, no answer in time).
3. `bump-ident.sh`, a script and not a commit, so that it works on any base (see "Building and flashing the module").

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
git fetch <this repo> repro/module-hold
git checkout -b hold-master upstream/master
git cherry-pick <first commit of the branch>^..<last commit of the branch>
```

On the head of PR #1071 (`fix/wifi-tx-nowait`) or of #1078 (`fix/wifi-uart-rx-overflow`): the same cherry-pick on a
branch made from that head. No conflicts on `b9cdfe261` (the merge of master into #1071), on `49074a0d2` (the #1078 head)
or on master `085aad730`.

Red and green need the same hold build on both sides: RED is master plus this branch, GREEN is the PR head plus this
branch. Then only the code under test differs between the two images.

## Building and flashing the module

The module change is in the three module projects, each built the usual way with its own ESP-IDF project
(`software/wifi/raw_u64`, `software/wifi/raw_c3`, `software/u64ctrl`). The firmware update image carries the module.

The updater reflashes a module only when the image's version differs from the module's (U64/U64E) or is higher (C64
Ultimate, Ultimate 64 Elite II, U2+L). The module change alone would be skipped. After the cherry-pick run
`repro/module-hold/bump-ident.sh` from the repository root: it raises `IDENT_MINOR` (and the version in `IDENT_STRING`)
by 100 in the three modules, above any stock module. Use the same bump on the red and the green build. Consequences:

- On the Ultimate 64 Elite (`!=` rule) a later stock image replaces the hold module by itself.
- On the C64 Ultimate and the U2+L (upgrade-only) a later stock image will say the module is newer and keep it.
  To go back to the stock module, build one update image with the module version check forced (change the version
  comparison in the updater's ESP32 step to always flash), or lower the version of your hold build below the stock one
  and force-flash the first time. A hold module left on a device is otherwise harmless: it answers only `0xB1`.
- Check with the UCI command: on a stock module `03 E5 00 00 00 00` answers `99,HOLD NOT SUPPORTED`, on the hold
  module it answers `00,OK` and 8 data bytes. (Ending a hold with `ms` = 0 also sends the `0x6E` event, whose value then
  means nothing if no hold ran.)

## Driving the hold for #1071

Settings of the recorded runs: Ethernet and WiFi both connected; a host pings the device over Ethernet every 100 ms and
polls REST in a loop; another host sends a steady 300 packets/s UDP stream to the device's WiFi address, so the host's
WiFi TX path stays busy; then three holds of 3000 ms, 30 s apart.

1. Send `03 E5 b8 0b 00 00` (3000 ms) on the UCI network target. The answer is `00,OK` with data `00 00 00 00 b8 0b 00 00`
   at once. The hold runs on the module and ends by itself.
2. During the hold read the largest gap between Ethernet ping replies, the ping loss, and the largest REST latency.
3. Between holds wait for the module to recover (WiFi ping answers again).

## What to expect for #1071

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

## Driving the hold for #1078

Settings: the device is on WiFi with its WiFi address reachable from the host, Ethernet unplugged (the load must go over
the module), "Command Interface" enabled, and let it settle. Keep the hold at 1.5 s.

1. Load from the host, started a second before the hold and kept up for about 3 s: six streams of full-size echo requests
   to the device's WiFi address. Each reply is a 1500 byte frame from the Ultimate to the module, which fills the
   module's RX FIFO: `for i in 1 2 3 4 5 6; do ping -f -s 1472 -w 3 <wifi-ip> & done; wait` (Linux, `-f` needs root).
2. Start the hold while the load runs: `03 E5 <arg u32 LE>` with `arg = 1500 | 0x80000000` (RTS off), i.e. `03 E5 dc 05 00 80`.
   The control with RTS on is `arg = 1500`. Expect `00,OK` with data `00 00 00 00 dc 05 00 00` at once.
3. After the hold and the load wait 3 s, then ask the module something that needs it (`03 E5 00 00 00 00` is enough; or
   ping the device, or look at the WiFi row).

| build | hold | console event | what follows |
|---|---|---|---|
| master or #1078, RTS on (control) | `1500` | `Ev 6E ... Seq: 122..127` (no 0x8000 bit: the Ultimate was held off at the RTS threshold) | module answers, no loss |
| #1078 (GREEN), RTS off | `1500 \| 0x80000000` | `Seq: 32896` (0x8080: overflow seen, FIFO full) | module keeps answering, no ping loss, the echoes carry on |
| master (RED), RTS off | `1500 \| 0x80000000` | `Seq: 32896` too | the damaged stream is taken for frames, the link is dead: `03 E5 0` returns `86,INTERNAL ERROR` or no answer, ping loss 100 %, WiFi Disable/Enable does not bring it back; plan on a power cycle after a RED run |

The event is the same on both builds, since it is read before the fix can act: it proves that the overflow happened. The
difference is what the module does afterwards. If the RTS-off row shows `Seq` without the 0x8000 bit the load was too
small (raise the streams or the hold time once): that is inconclusive. If it shows no event at all, the module in the
run does not have this branch (version not bumped, so not installed).

Recorded on a C64 Ultimate with our own bench build of the module (which also has an `rx_fifo_ovf` counter that this
branch does not have), six streams of 1472 byte echoes, 3 s, 1500 ms hold: without the #1078 handler and RTS on, 81..83
echoes answered per stream and the module answers afterwards; without the handler and RTS off, 37..39 echoes and then
nothing, the module dead until a mains cycle; with the handler and RTS on, 88..90 and alive; with the handler and RTS
off, 88..91, alive, no wedge (`rx_fifo_ovf` 1).

The recorded #1071 Elite runs used the hold module from the earlier bench images; this branch is a port of that code to the
current master, built to compile for the three module projects but not yet run on a device by us.
