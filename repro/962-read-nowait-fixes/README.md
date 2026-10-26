# Fixes for a no-wait UCI network READ (GideonZ/1541ultimate#962)

Each program below changed behaviour when READ on an empty socket returns at once instead of waiting 40 ms. Every fix does the same thing: it bounds the wait by time instead of by the number of READs, and loops until the needed bytes have arrived. That way the program behaves the same whatever an empty READ costs (0 ms, 40 ms, or the ~4 s of v3.12).

| Diff | Upstream repo @ commit | File | Change | Size |
|---|---|---|---|---|
| `c64uploader.diff` | c64uploader/c64uploader @ `d826b8d` | `c64client/src/ultimate.c` (`uci_tcp_nextchar`, 838-862) | 500-try retry cap becomes a 20 s timeout on the CIA1 TOD clock | +33/-8 |
| `ultimateii-dos-lib.diff` | xlar54/ultimateii-dos-lib @ `3a38e69` | `src/samples/ultimateterm.c` (`handle_telnet_iac`, 1447, 1455) | each telnet negotiation byte is polled until it arrives, the connection closes, or 2 s pass (`clock()`) | +22/-5 |
| `C64U-H2H.diff` | mfidder2026/C64U-H2H @ `2b266bf` | `src/main.c` (`link()`, 663-746) | no screen line while a PONG is due (up to 50 ms), at least 4 lines/s | +9/-2 |
| `ultimate-uci-sdk.diff` | barryw/ultimate-uci-sdk @ `5ec72f5` | `tests/hardware/ucitest.c` (1389-1394) | 40-try poll becomes a 2 s timeout (`clock()`); test program only | +9/-6 |

Apply with `git apply <diff>` at the listed commit. Builds: c64uploader with oscar64 v1.32.271; the others with cc65 2.18 (`cl65`).

Tested on a C64 Ultimate (core 1.50, 1 MHz) with firmware whose READ never waits, over WiFi and over Ethernet: c64uploader and UltimateTerm pass every case the unpatched builds failed (results in the issue). The C64U-H2H change made no measurable difference to its round trip. The ucitest change compiles but has not been run. None of the fixed builds has been run on 40 ms firmware.
