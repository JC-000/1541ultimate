# UCI network READ ($03 $10): app inventory for the #1087 review

Sources: READ-40MS-SURVEY.md, GEOS-C64OS-SURVEY.md (earlier desk surveys, source read), plus a new sweep 2026-11-12:
gh code search (uii_socketread/uii_tcpconnect/uii_tcp_nextchar/NET_CMD_SOCKET_READ/NET_CMD_TCP_SOCKET_CONNECT/uci_socket/
ULT_NET_SOCK_READ/ultimate_net_read/UCI_TARGET_NETWORK) + web. The sweep returned no repo that was not already known except
iss-tracker-u64, jesters_maze, ultimate-uci-oscar64, UBoot64-v2, c64jp, ristola/C64, Tachyon-RL (header only). Code search is
rate limited and misses closed-source, BASIC and CSDb-only releases. Clones: ~/Documents/1541u-ext/read962-1087/.
V = verified from source read; I = inferred. "W" = 40 ms wait (3.12a-3.15), "0" = no wait.

## Affected (behaviour changes)
| App (source) | Read pattern | Effect under no-wait | Under 40 ms / older fw | Fix | Basis |
|---|---|---|---|---|---|
| c64uploader (c64uploader/c64uploader d826b8d, c64client/src/ultimate.c:838-862) | retry on -1, `++retries > 500` gives up | silent-server patience 20 s -> 1.6 s; greetings >= 2 s refused. Measured on C64U | W: 20.2 s. <=3.11: same as no-wait. v3.12 (4 s/READ): 500 x 4 s ~ 33 min | time-based timeout (CIA TOD), +33/-8, hw-proven | V + measured |
| UltimateTerm / u-sample (xlar54/ultimateii-dos-lib 3a38e69, samples/ultimateterm.c:1447,1455) | telnet IAC verb then option, return value of READ ignored (source has a TODO), uses uii_data[2] regardless | negotiation split across segments is read wrongly (15 ms split: 0/5 correct) | W: 3/5 at 15 ms split, 0/5 at 60 ms (already flaky). <=3.11: as no-wait. v3.12: 4 s wait masks it (I) | poll each byte until arrived/closed/2 s, +22/-5, 15/15 hw | V + measured |
| u-sample.c (same repo, :84-88) | `while (uii_success()) READ 1` right after connect | first empty READ ends loop: banner usually not printed | W: prints only if greeting < 40 ms. Demo only | none needed (demo) | V |
| jesters_maze (guidobonerz, first commit 2026-01-18; src/game/jester.asm:447-465 handleResponse, ultimate_dos.asm) | UDP to the author's Go server (maschine1.de:64646; a LOCAL build flag points at a LAN host): after each move, sends, then ONE READ of 3 bytes, no retry, uses dataBuffer+2..+4 whether or not data came. On an empty reply `readData` leaves count $FFFF, dataBuffer+2 stale, +3 zero; the bytes are written to $0400-$0402 which the next move reads (`and $0400`) | the clearest affected program. The reply must already be queued when READ is issued: with 40 ms it works on a LAN (RTT of a few ms) and fails beyond ~40 ms; with no-wait a LAN reply is not yet there either, so it fails there too. The late reply stays queued, the next READ returns the PREVIOUS reply: the game runs one reply behind | 40 ms: LAN only. <=3.11: as no-wait. v3.12 (4 s): works | retry until count != $FFFF, 3 s limit (jesters_maze.diff) | V (source); never run |
| ristola/C64 "OkExt" BASIC ext (hello/bank11_content.asm HTTPGET, TELNET) | HTTPGET: one READ 512 after the request. BUT `net_tcp_connect` leaves 5 (the "00,OK" status byte count written by `ult_read_status`'s `sty ult_tmp`) in ult_tmp, and both commands use ult_tmp as the socket handle | NOT affected by #1087: HTTPGET and TELNET use the wrong socket on every firmware, so they fail before any timing matters (V, source; never run). The ristola source comment "READ can block indefinitely" is consistent with a bad handle | n/a | okext-httpget.diff fixes the handle (net_tcp_connect saves it to telnet_sock and restores ult_tmp; WRITE and READ read it from telnet_sock) and, once it works, bounds HTTPGET's wait by time | V |
| barryw/ultimate-uci-sdk tests/hardware/ucitest.c:1380-1407 | 40-try poll for echo | bound shrinks ~1.7 s -> ~0.2 s: test can fail on slow peer | test only, not a product | 40 tries -> 2 s | V |
| h-o-soft/c64jp oscar64_term xmodem.c:487-496 `drain_tcp` | READ 512 until count <= 0 before XMODEM | stops at first gap; data in flight within the old 40 ms window is no longer drained, may land as stray first byte | minor, I | none yet | V (source), effect I |

## Added after review (2026-11-12)
| App | Source | Pattern | Verdict |
|---|---|---|---|
| SEE64YOU (dannykeat-projects, first commit 2026-09-23) | client/src/publisher/standard_transport.c:241 (also 4096-poll cap), standalone_direct.c:303 (legacy Publisher, not in the shipped package), browser/http.c:136 | HTTP over UCI: loop ends after 512 consecutive empty READs | AFFECTED: each empty-READ pass costs about 83 ms at 40 ms and about 46 ms without the wait (program overhead included), so patience is 42.5 s today and 23.5 s with no wait (measured on the C64U against a delayed-reply server). A slower reply is reported as a protocol error. Fix: 45 s without data on clock() (real time on the C64U), hardware tested on both firmware behaviours. V + measured |
| ntp2ultimate (Pernotto, 2021-01-21) | u-time.c:79-84 | UDP request, then one `uii_socketread(socket, 50)` straight after, CheckStatus on the result | written for a READ that does not wait; unaffected by no-wait relative to its design. Whether it worked reliably on 3.0-3.11 depends on the reply beating the READ (not tested). V |

Dates (first commit of the UCI code, gh api): xlar54 lib 2018-08; ultimateterm.c 2018-12 with handle_telnet_iac added 2021-02-23 (5c20f81); 8bit-Unity net-tcp.c 2021-01; DMBoot 2020-11; MultiRogueLike UCI client 2020-03; ntp2ultimate 2021-01; GeoUTools 2023-01; UBoot64 2023-09; CPMUTools 2023-10; iss-tracker-u64 2023-11 = 9 programs/libraries written before 57c7c8a6a (2025-05-22), all against no wait. After it (11): UBoot64-v2 2025-08, c64jp 2025-08, c64uploader 2026-01, jesters_maze 2026-01, Commodore64_Gameserver 2026-01, ReadyOs 2026-04, c64u-radar 2026-07, OkExt 2026-07, barryw SDK 2026-08, SEE64YOU 2026-09, C64U-H2H 2026-10. (ultimate-uci-oscar64, 2026-10, is a copy of the xahmol library and is not counted.) Affected since May 2025: c64uploader, jesters_maze, SEE64YOU (plus the barryw test and c64jp drain). The one affected program older than that is UltimateTerm's telnet negotiation (2021): its race exists on every no-wait firmware; v3.12's 4 s masked it.
Evidence that authors already worked around a non-waiting READ: xahmol/UBoot64 commit 05631e7 (2023-09-08), src/time.c:193: "Add delay of a second to avoid time to wait on response being too short".

## Unknown
| KANAL 7 (UPIC game, kanal7.8bitcavern.de) | closed source, no binary yet (itch.io "coming"), no repo. Page: Command Interface used non-blocking, one command per frame; two-player via relay vermittler.py; needs fw >= 3.15 for HTTP high scores. Cannot be analysed. Its stated design (one command per frame, raster-critical Upic at 48/64 MHz) is incompatible with a 40 ms READ stall (2 PAL frames), so it either avoids empty READs or benefits from no-wait. Ask the author. | I |

## Unaffected or faster (no dependence on a blocking READ)
| App | Why | Basis |
|---|---|---|
| xlar54 lib uii_tcp_nextchar/nextline; ultimateterm main loop, XMODEM; u-echoserver; u-chat; geouterm | unbounded spin or one READ per loop; spin gets faster, no correctness change | V |
| xahmol UBoot64, UBoot64-v2, GeoUTools, CPMUTools, DMBoot, ultimate-uci-oscar64 (lib copies) | NTP: 1 s `delay` before each READ, count-bounded; lib copy = same nextchar spin | V |
| 8bit-Unity net-tcp.c:146, net-udp.c:168 | `while READ < 1` bounded by wall-clock `clock()` | V |
| k6lcm/c64u-radar read_blob | clock()-deadline loop | V |
| LeifBloomquist/iss-tracker-u64 network.c:111 | `-1: continue`, returns first chunk | V |
| LeifBloomquist/MultiRogueLike | one READ per frame; bootloader spin unbounded (hotter, still ends on close) | V |
| barryw/ultimate-uci-sdk | documents READ as non-waiting, callers poll | V |
| mfidder2026/C64U-H2H | measures read latency; polls; our fix optional (no measurable effect on idle air) | V + measured |
| mfidder2026/Commodore64_Gameserver (WoW) | async driver built around the 40 ms; its docs say per-frame synchronous polling is not feasible with a 42 ms empty READ (games/wizardofwor/docs/PROMPT_WoW_LAN.md:66). Faster under no wait, no functional change | V |
| ReadyOS-C64/ReadyOs readyirc | treats 02 as "no data, no delay"; distinguishes 01 | V |
| JC-000 c64-https, c64-wireguard, nes-c64-crossplay, c64-test-harness (ours) | c64-https neutral measured; crossplay lobby bug of the c64uploader class already fixed | V + measured |
| T-Pau/Tachyon-RL | declaration in net.h only, no implementation | V |

## Author statement (#1087, xahmol, 2026-11-12)
xahmol (UBoot64, UBoot64-v2, GeoUTools, CPMUTools, DMBoot, ultimate-uci-oscar64) wrote: "I think that the assessment of topic starter is probably correct that my code already has a time out loop", and "I prefer improved stability over forced backward compatibility, of course preferably with early communication on breaking changes." He is busy updating his tools for 3.15a. The NTP detail below (1 s delay before each READ, UII_SUCCESS ends it) is from our source read, not from him. Source check agrees: his only network READ use is NTP (UBoot64-v2 src/time.c:222-245, time.c, time_synch.c, DMBoot config.c:144-170): up to 4-5 attempts, each preceded by a 1 s `delay`, ends on `UII_SUCCESS`. Wait-independent. The lib copies also carry the unbounded `uii_tcp_nextchar` spin, which no xahmol tool calls (V).

## Not UCI network READ
C64 OS (SwiftLink-emulation drivers; UCI only as RTC), GEOS/MegaPatch/Wheels (no UCI driver found), geoLink (RR-Net), IP65/Contiki/Lunix (no UCI driver), c64cast (Ultimate DMA socket on TCP 64, not UCI), xahmol/u64-bbcbasic (python host tools only).

## Counts (distinct programs/libraries, excluding our own and the oscar64 copy): 20
Written before 2025-05-22: 9 (all against no wait). Since: 11.
Affected by #1087: 3 products written since May 2025 (c64uploader, jesters_maze, SEE64YOU), UltimateTerm's telnet negotiation (2021, race exists on 3.11), and two minor (barryw ucitest, test only; c64jp drain_tcp, inferred; u-sample demo).
Not affected, already broken: OkExt HTTPGET/TELNET. Unknown: KANAL 7. Unaffected or faster: the rest.
Fixes: c64uploader, UltimateTerm (fork branch, hardware tested); jesters_maze, SEE64YOU, OkExt (fixes/, unpublished: will be published; SEE64YOU compiles file by file, OkExt bank 11 assembles, jesters_maze not built).
