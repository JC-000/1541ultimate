# Firmware timeline of the UCI network READ wait (verified at tags, 2026-11-12)

Mechanism: `open_socket()` in software/io/network/network_target.cc sets SO_RCVTIMEO on every UCI socket; `read_socket()` does one lwip_recv(); a timeout yields count $FFFF + "02,NO DATA: n".

| Release | network_target.cc:229-232 | lwip | Effective wait | Evidence |
|---|---|---|---|---|
| v3.10 (2021-07-24), v3.11 (2023-12-28) | `tv_sec = 4; tv_usec = 4;` | software/lwip-1.4.1; v3.11 lwipopts.h:980 `LWIP_SO_RCVTIMEO 1` | 0 ms (non-blocking) | lwip-1.4.1 src/api/sockets.c:2132-2133 `netconn_set_recvtimeout(conn, *(int*)optval)` reads the FIRST int of the timeval = tv_sec = 4 (ms). src/sys_arch.c fetch: `xQueueReceive(..., ulTimeOut/portTICK_PERIOD_MS)` = 4/5 = 0 ticks (FreeRTOSConfig.h:11 tick 200 Hz). 0 ticks = return at once. |
| v3.12beta (2025-03-18), v3.12 (2025-05-11) | same, unchanged | software/lwip submodule fbd597e (lwip 2.2.0, from 7ea644d3e 2025-01-11); lwipopts has no LWIP_SO_SNDRCVTIMEO_NONSTANDARD, opt.h:2102 default 0 | 4000 ms | lwip sockets.c:243 `GET_MS = tv_sec*1000 + tv_usec/1000`; the same `4/4` now means 4.000 s |
| 57c7c8a6a (2025-05-22), commit message "Delays in socket polling set correctly for LWIP 2.1": `tv_sec = 0; tv_usec = 40000; // 40 ms` | | | 40 ms | same commit also changes ftpd.cc and socket_gui.cc from `tv_sec = 20; // bug in lwip; this is just used directly as tick value` to 100 ms / 200 ms: the author's own comments show the old values were tick-style numbers and the commit re-expresses them for lwip 2.x |
| v3.12a (tag 2025-06-01; official page dates it 2025-06-19), v3.14, v3.15, v3.15a | `tv_usec = 40000` | lwip 2.2.0 | 40 ms | git show of each tag |

Notes
- In the 4/4 era the author intended a small tick-style timeout (see his "used directly as tick value" comments); it never meant 4 s. 57c7c8a6a is described by its own message as a correction for lwip 2.x.
- Correction to the earlier memory note: the "~20 ms" figure belongs to ftpd/socket_gui values, not network_target; network_target is 4 ms -> 0 ticks.
- Release notes: ultimate_releases has changes_3.10f/i/j and changes_3.11 only; none mentions socket/UCI READ timing (grep: socket, uci, timeout, lwip). No change list exists there for 3.12-3.15 (the firmware page says one will follow). docs/uci/network_target.rst (2da134b) lists only status 00 and 01 for READ; it documents neither "02 NO DATA" nor any wait. GitHub releases of GideonZ/1541ultimate stop at v3.4. So the wait, its removal (lwip 2.x upgrade, 4 s) and the 40 ms were never documented.
- Not tested: which lwip the released v3.12 binaries used (only that 7ea644d3e is an ancestor of the tag and lwip is a submodule pinned at fbd597e in the tag tree).

## Were any breaks reported while READ waited 4 s? (searched 2026-11-12)
Searched GideonZ/1541ultimate issues (UCI socket, READ_SOCKET, socketread, network target, tcp connect; plus a full listing of the 84 issues created 2025-03-01..2025-09-30). No issue or PR from the v3.12beta/v3.12 period (tags 2025-03-18, 2025-05-11) reports slow or stalled UCI network reads. The first UCI READ issues are 2026-08 (#802, #808, #807, #847), the first about the wait is #1086. Web search found nothing either. Not searched: CSDb, Lemon64 and other forums (not reachable through search), so absence there is unknown.
Related reports from the same period, same root cause class (lwip 2.x timeval units) on OTHER paths:
- #510 "Retroterm on 3.12 II+L" (2025-05-28): modem emulation set `tv_sec = loopDelay*5` (seconds, not ticks) at modem.cc:152 in v3.12; keyboard dead, disconnects. Fixed in the modem rewrite (v3.12a: `tv_sec = 0; tv_usec = loopDelay*1000`).
- #509 "Flaky telnet UI with 3.11 and 3.12" (2025-05-26): UI telnet (socket_gui, old `tv_sec = 23`), hardened by 3.15.
- 57c7c8a6a (2025-05-22) landed 11 days after v3.12 (2025-05-11) and 65 days after v3.12beta (2025-03-18).
Reading: nobody reported a UCI READ break across 20 ms(0) -> 4 s -> 40 ms. But the same unit change was reported as breaking on the modem path within 17 days of v3.12 and Gideon fixed the UCI timeout himself 11 days after v3.12, so "nobody noticed the 4 s" is only true for UCI READ users, and the lwip units change was noticed elsewhere. Say that, not "nobody noticed anything".

## Corrections after review (2026-11-12)
- The 4/4 line dates from 915cfbe71 (2015-07-28) and is in 3.0c (tag 2016-10-16); lwipopts has LWIP_SO_RCVTIMEO 1 there too. So 0 ticks applies to every release from 3.0 to v3.11, not only 3.10/3.11.
- software/lwip at fbd597e is a 2.2.1 development snapshot (init.h: 2.2.1, LWIP_RC_DEVELOPMENT), not release 2.2.0.
- Documentation: doc/uci_network_target.docx (git date 2026-03-15; also doc/uci_network_target_v1.0.pdf) lists for NET_CMD_READ_SOCKET only "00,OK" and "01,CONNECTION CLOSED BY HOST" and no wait. The readthedocs network_target.rst (2da134b) says the same.
- The C64U line has only had 40 ms (its firmware line starts after 57c7c8a6a); U64/U2+ had 0, 4 s, 40 ms.
- #510 (Retroterm on 3.12) is still OPEN; its link to the timeout change is my inference from modem.cc, not shown by the reporter or the maintainer.
- Withdrawn from the drafts: "programs already lived through behaviour as strict as no-wait" and "no report says programs do not depend on its length".
- The earlier "~11 ms C64 turnaround" figure came from the H2H peer-side measurement (includes the program's own processing); it is not a UCI turnaround and is not used.
