# Reproduction kit: Nios TLS vs the ESP32 TLS offload (#997), matched run on an Ultimate 64 Elite

This kit rebuilds both images and reruns both series of the comparison made on 2026-10-26: Barry's TLS client running on the Nios (`barryw/1541ultimate`, branch `bench/nios-tls-2026-10-24`) against the ESP32 TLS offload of #997, driven by a bench-only Nios task so that both sides run the same fixture, the same peer, the same payload and the same service-impact probes. The per-run results of that day are in `results/`.

Everything here is work-in-progress material for the discussion on #997. The ESP-side module number is a placeholder that is assigned at merge; none is quoted here.

Contents:

| path | what |
|---|---|
| `README.md` | this file |
| `set-barry-peer.sh` | the peer-address change on top of Barry's tree (two `inet_addr` literals) |
| `scripts/tlsb.py` | shared helpers (harness client, device lock, summary maths) |
| `scripts/tlsb_cfg.py` | SET the device settings a series needs, read each back, record |
| `scripts/tls_bench_nios.py` | series A and A-matched (Barry's collector logic on the harness) |
| `scripts/service_impact.py` | series L (REST latency) and F (FTP throughput) under TLS load, plus `stage` |
| `scripts/peers.sh` | starts and stops Barry's two peer servers and an optional packet capture |
| `scripts/capture_phase.py`, `scripts/test_capture_phase.py` | phase clock from a capture (optional) and its synthetic-pcap selftest |
| `results/{nios,niosF,resp,respF}/` | the result JSONs of the 2026-10-26 run, addresses and identifiers replaced by placeholders |

## What each side measures

Both images answer `PUT /v1/machine:tls_bench` (starts a FreeRTOS task on the Nios) and `GET /v1/machine:tls_bench` (`idle|running|complete`, then the result JSON). Both tasks do the same thing: a TLS connection to the peer on port 18443 with the test CA as trust anchor, send one `B`, read 256 KiB and check every byte against `offset & 255`, then the same transfer over plain TCP on port 18444. Clock for both: `xTaskGetTickCount() * portTICK_PERIOD_MS`, the FreeRTOS tick at 200 Hz, so every figure is a multiple of 5 ms.

**Barry's side** (`software/api/tls_bench.cc` at `74f0112e4`): mbedTLS 3.6.7 runs on the Nios. The task calls lwIP and mbedTLS directly.

**Responder side** (`software/api/esp_tls_bench.cc` on this branch): the task calls the product's own command target (`extern NetworkTarget net`, `network_target.cc:18`) through its public `parse_command()` / `get_more_data()` with the byte-exact commands a C64 sends, minus the UCI: `$22 TRUST_CA` (the 408-byte CA, every run, untimed), one `$23 $FF` STATS RPC timed alone (`stats_rpc_ms`), `$21 OPEN_TLS` (`tls_prepare`, module OPEN RPC, resolve, socket, connect, `tls_handshake`, STATS RPC, reply), `$23 h` TLS_INFO, `$11` WRITE `B`, `$10` READ 1024 repeatedly, and a final READ that must end `01,CONNECTION CLOSED BY HOST`. All TLS crypto runs on the ESP32 module, reached over the UART RPC. The plain leg is Barry's `run_plain` copied line for line.

Where each timer starts and stops (Barry's lines from `tls_bench.cc` at `74f0112e4`; ours from `esp_tls_bench.cc` and `network_target_tls.cc` on this branch):

| field | Barry | responder |
|---|---|---|
| `tcp_ms` | `:184` .. `:200` (socket create, two setsockopt, `lwip_connect`) | derived: `open_total_ms - handshake_ms`. Covers everything in OPEN_TLS before the handshake window: SNTP read, module OPEN RPC over the UART, resolve, socket, connect. Larger than Barry's by the OPEN RPC. |
| `setup_ms` | `:204` .. `:227` (CA parse, DRBG seed, config, `ssl_setup`, hostname, `set_bio`) | 0. The module holds the session setup; the CA upload is once per boot and untimed. Folded into `tcp_ms`. |
| `handshake_ms` | `:231` .. `:239`, right after `mbedtls_ssl_handshake` returns | `e->handshake_ms`: `network_target_tls.cc:720` (first line of `tls_handshake`, after TCP connect and module OPEN) .. `:827` (after the post-handshake STATS RPC), read back with TLS_INFO (`esp_tls_bench.cc:193-199`). Includes every step RPC over the UART, the socket traffic of the handshake flights, and one STATS RPC. |
| `open_total_ms` | n/a | `esp_tls_bench.cc:181` .. `:183` around the whole `$21` `parse_command` |
| `transfer_ms` | `:257` (right after `ssl_write('B')` returns) .. `:274` (last byte checked into `buffer[1024]`) | `esp_tls_bench.cc:212` (right after the WRITE `B` command returns) .. `:233` (last byte checked into `buffer[1024]`). Same points. Inside: per READ one `parse_command`, one `tls_read` (an `lwip_recv` plus one `wifi_tls_step` RPC per up to 1024 B), a memcpy and the byte check. |
| `plain_tcp_ms` | `:127` .. `:133` | `esp_tls_bench.cc:94` .. `:100` (same code) |
| `plain_transfer_ms` | `:138` .. `:155` | `esp_tls_bench.cc:105` .. `:122` (same code) |

To compare connection cost, use `tcp_ms + setup_ms + handshake_ms` for Barry and `open_total_ms` for the responder. The responder's `tcp_ms` alone and `setup_ms` are not comparable to Barry's.

The responder fails a run unless the session is TLS 1.2 (0x0303), suite 0xCCA9 (ECDHE-ECDSA ChaCha20-Poly1305) and group 0x0017 (secp256r1), so both sides measure the same session. Every responder run in `results/resp/` reports exactly that.

## Differences that remain, and which way they bias

1. The TLS engine. Barry's is mbedTLS on the Nios, ours is the ESP32 module behind a UART RPC. That is the thing being measured, not a bias.
2. `handshake_ms` includes one STATS RPC (`network_target_tls.cc:813-815`) that Barry's window does not. It inflates the responder by `stats_rpc_ms` (2.5 to 5 ms against a handshake of about 1565 ms). Bias against the responder, negligible.
3. The responder's ClientHello offers a TLS 1.3 key share (X25519) and the peer answers with 1.2, and every handshake step is a UART round trip. Neither is in Barry's fixture. Bias against the responder.
4. READ goes through the command layer (5-byte command, 2-byte header, two reply blocks for a 1024-byte reply: 893 payload bytes in the first block, then a continuation fetched with `get_more_data`) where Barry calls `ssl_read` directly. A small CPU cost per READ that belongs to the product path. Bias against the responder. A C64 program would use 1472-byte reads; the task uses 1024 to match Barry's buffer.
5. The responder's TLS socket is non-blocking with `TCP_NODELAY` (`tls_socket_options`, `network_target_tls.cc:587`); Barry's is blocking with 180 s timeouts. Not expected to matter at this payload size; not measured.
6. Entropy and time: the module uses the ESP32 hardware RNG (it needs the Wi-Fi radio on), time comes from SNTP and must be at least 2025-01-01 or OPEN answers `92,NO TRUSTED TIME`. Barry's fixture uses deterministic entropy and the RTC. Not expected to move the figures; not measured.
7. `verify_flags` is always 0 on the responder: a failed verification is a refused OPEN (error -102, text in `status`).
8. The responder task drives the global `net` that the C64's UCI uses, from a second task, with no locking. That is only safe with the C64 idle. See the run rules.
9. #997 does not send `close_notify` back when the peer closes: `tls_end` (`network_target_tls.cc:1291-1292`) closes the entry without one. Barry's fixture sends it (`tls_bench.cc:276`). It is not inside either timed window. Expect `SSLEOFError` lines in the peer's TLS log for every responder run; they are not failures.

## Build both images

Toolchains are the repository's own: see `README.txt` at the repository root (Nios II toolchain for the application, ESP-IDF 6.0.x for the ESP32 module of the responder image, ESP-IDF 5.3.1 for the module of Barry's image if you build it). Flash only on a device you can recover.

**Barry's image.** Base `74f0112e4` ("Document fresh build prerequisites and curve pinning") on branch `bench/nios-tls-2026-10-24` of `https://github.com/barryw/1541ultimate`. His README in that tree (`benchmarks/nios-tls/README.md`) is the reference for the peer and the build.

```sh
git clone https://github.com/barryw/1541ultimate barry && cd barry
git checkout 74f0112e4 && git submodule update --init --recursive      # mbedTLS 3.6.7, 068ff080
sh <this kit>/repro/997-tls-bench/set-barry-peer.sh . <peer-ip>         # the only change: his fixed peer address, two lines
make u64_no_esp                                                          # or make u64 where the ESP-IDF toolchain is set up
```

`set-barry-peer.sh` replaces the two `inet_addr("...")` literals in `software/api/tls_bench.cc` (`run_plain()` at line 126, `run_benchmark()` at line 195) with the address of the machine that runs the peers, refuses to run unless it finds exactly two, and prints the diff. The measured image was this tree plus that change, `make u64_no_esp`; the ESP module was not in the measured path. The result is `update.u64`.

**Responder image.** This branch (`repro/997-tls-bench`). The commit below the kit commit is `4aa801506`, which is #997 on the ESP-IDF 6 work (`8fff23b3c`) plus three bench-only commits: `software/api/esp_tls_bench.cc` (new), `esp_tls_bench_reply.h`, `tls_bench_ca.h` (Barry's CA as DER, copied from his tree), one line in `target/u64/nios2/ultimate/Makefile`, `openapi_check` dropped from the `u64` and `u64_no_esp` targets so the bench route stays undocumented as in Barry's tree, and `INCLUDE_uxTaskGetStackHighWaterMark` set to 1 in `software/FreeRTOS/Source/FreeRTOSConfig.h` (as Barry's branch does). The kit commit on top changes one thing in the source: `BENCH_PEER` in `esp_tls_bench.cc` is now the placeholder `192.0.2.10`. Set it to the address of the machine that runs the peers before building.

```sh
git clone https://github.com/JC-000/1541ultimate && cd 1541ultimate
git checkout repro/997-tls-bench && git submodule update --init --recursive
$EDITOR software/api/esp_tls_bench.cc          # BENCH_PEER = <peer-ip>
export IDF_PATH=...                             # ESP-IDF 6.0.x, as the root README.txt describes
make u64                                        # builds the ESP32 module too; result: update.u64
```

The images used on 2026-10-26 were built in a container; they are not byte-reproducible (the build embeds the git hash and a timestamp), so compare behaviour, not hashes. The responder image reports git hash `4aa801506`.

## Test-server setup (the peer)

Use Barry's peer programs from his tree at `74f0112e4`, unmodified: `benchmarks/nios-tls/peer/server.py` (TLS, port 18443), `plain_server.py` (plain TCP, port 18444), with `server.pem`, `server.key`, `ca.pem`, `ca.der` next to them. They are not copied here. Run them on a machine on the same wired segment as the device, and allow TCP 18443 and 18444 through its firewall.

- `server.py` forces TLS 1.2 only, cipher list `ECDHE-ECDSA-CHACHA20-POLY1305`, curve `prime256v1`, no session tickets. It waits for one `B`, sends `bytes(range(256)) * 1024` (256 KiB), then `unwrap()`s (close_notify). It logs one JSON line per connection (peer address, version, cipher, resumed, bytes, elapsed). `resumed` must be false in every line.
- `plain_server.py` sends the same bytes on 18444.
- The test CA and the server certificate (`CN=bench.local`, P-256) are valid from 2026-10-24 to 2027-01-22 UTC. After that date every run fails verification; regenerate both and rebuild the images (Barry's image embeds the CA, so does `tls_bench_ca.h` here).
- `scripts/peers.sh` starts both servers with their logs in an output directory, and optionally a capture:

```sh
export PEER_DIR=<barry tree>/benchmarks/nios-tls/peer
export DEVICE_IP=<device ip>        # only for the capture
export CAPTURE_IFACE=<iface>        # optional; needs dumpcap (Wireshark) and capture permission
sh scripts/peers.sh start runs/nios
...
sh scripts/peers.sh stop runs/nios   # writes sha256.txt (peer scripts, pcap) and python.txt
```

## Device configuration

Set by `scripts/tlsb_cfg.py set turbo` and read back (exit 1 if any read-back differs); the record goes into every result JSON:

- Turbo Control `Manual`, CPU Speed `48` (the `turbo` profile)
- WiFi Enabled `Enabled` (the ESP32 needs the radio for its entropy; the Nios series runs with the same setting so both carry the same load), traffic still goes over the wire
- SNTP Enable `Enabled` (the responder's CUSTOM-CA trust needs trusted time; Barry's side uses the RTC, which must be 2025 or later)
- Command Interface `Enabled`
- System Mode (PAL or NTSC) is read and recorded, never changed. The 2026-10-26 device ran NTSC.
- After flashing, do a configuration reset and then SET the above; do not carry settings over. Wired Ethernet connected, device and peer on the same subnet.

Device under test in 2026-10-26: Ultimate 64 Elite, core 1.50, firmware 3.15a.

## Run rules

- The C64 is idle: no program running, and no C64 reset between the PUT and the completion of a series. The responder task shares `net`, its sockets and the TLS table with the UCI target and takes no lock; a C64 reset runs `tls_reset` underneath it.
- Nothing else talks to the device during a series, except the probes of L and F. Do not run other device tests at the same time.
- The device is in the same state for both images: same profile, same peer, wired.
- Run the series in the order A, A-matched, L, F per image. One warm-up run is discarded by the collector, then 12 runs.

## The four series

Install the c64-test-harness package once (0.13.1 was used; https://github.com/JC-000/c64-test-harness). Run every script as `python3 -I`; `-I` makes the scripts add their own directory to the path. `--host` / `--peer` default to the environment variables `TLSB_HOST` / `TLSB_PEER`.

```sh
export TLSB_HOST=<device ip>  TLSB_PEER=<peer ip>  PEER_DIR=<barry tree>/benchmarks/nios-tls/peer
export U64_CABLING_SETTLED=1                   # the harness' cabling sweep probes the whole /24; skip it
cd repro/997-tls-bench/scripts
RUN=../runs/nios                               # use ../runs/resp for the responder image
mkdir -p $RUN
python3 -I tlsb_cfg.py set turbo --out $RUN/cfg.json
sh peers.sh start $RUN

# 1. Barry's method (A): PUT, poll GET every 0.25 s, 12 runs; about 10 min on the Nios image, 2 min on the responder
python3 -I tls_bench_nios.py run --runs 12 --cfg $RUN/cfg.json --out $RUN/A.json

# 2. Matched (A-matched): the device is silent until the peers logged the run, then one GET (2 s retries)
python3 -I tls_bench_nios.py run --runs 12 --cfg $RUN/cfg.json --out $RUN/A-matched.json \
    --peer-logs $RUN/peer-tls.jsonl $RUN/peer-plain.jsonl

# 3. L: REST latency (get_info every 0.5 s): 30 idle samples, then 180 s with back-to-back TLS runs going
python3 -I service_impact.py L --build nios --cfg $RUN/cfg.json --out $RUN/L.json --peer-plain-log $RUN/peer-plain.jsonl

# 4. F: FTP download of a staged 4 MiB file: 10 idle, then back to back for 180 s under the same load
python3 -I service_impact.py stage                  # once per device: 4 MiB seeded-random file to /USB1/tlsbench/ftp4m.bin, sha256 in ftp4m.sha256
python3 -I service_impact.py F --build nios --cfg $RUN/cfg.json --out $RUN/F.json --peer-plain-log $RUN/peer-plain.jsonl

sh peers.sh stop $RUN
```

Run F in its own output directory with its own peers (the 2026-10-26 run used `runs/niosF` and `runs/respF`), so the F load and its capture are separate from L. `service_impact.py` exits 4 when the load generator stalled (series invalid), `tls_bench_nios.py` exits 5 when a run failed (the partial JSON is still written).

`--build nios` is the load generator for both images: both serve the same PUT/GET route. `scripts/capture_phase.py conns capture.pcapng` (with `TLSB_HOST` and, to detect a WiFi path, `TLSB_ETH_MAC`) derives per-connection phases from a capture, and `capture_phase.py tag conns.json L.json` stamps the L and F samples with the phase they fell in.

Offline selftests (no device needed): `python3 -I scripts/tls_bench_nios.py selftest`, `tlsb_cfg.py selftest`, `service_impact.py selftest`, `capture_phase.py selftest` (this one needs `tshark`).

The one private harness call is `tlsb.rest_call` (`Ultimate64Client._request`): the bench route has no public harness call. Everything else uses the harness' public API.

## Results of 2026-10-26

Medians in ms, 95th percentile in brackets, 12 runs per series after one warm-up. Files: Nios from `results/nios` (`A-nios.json`, `A-nios-matched.json`), responder from `results/resp`.

| metric | Nios A | responder A | Nios A-matched | responder A-matched |
|---|---|---|---|---|
| tcp_ms | 5 (10) | 10 (10) | 5 (5) | 0 (5) |
| setup_ms | 10 (15) | 0 (0) | 10 (15) | 0 (0) |
| handshake_ms | 35620 (35650) | 1565 (1570) | 34360 (34375) | 1565 (1570) |
| open_total_ms | n/a | 1575 (1575) | n/a | 1570 (1570) |
| stats_rpc_ms | n/a | 2.5 (5) | n/a | 5 (5) |
| transfer_ms (256 KiB) | 7275 (7300) | 2330 (2340) | 7022.5 (7055) | 2310 (2310) |
| plain_tcp_ms | 0 (5) | 0 (5) | 0 (5) | 0 (5) |
| plain_transfer_ms | 270 (270) | 275 (275) | 260 (260) | 265 (265) |

Connection cost compared as in the section above: Nios `tcp + setup + handshake` is about 35635 ms, responder `open_total` is 1575 ms. Derived from the medians: the handshake is about 22.8x shorter (A) and 22.0x shorter (matched), the transfer about 3.1x shorter. The plain leg is equal within tick noise (5 ms ticks), which shows the two images give the same plain-TCP path. All responder runs: error 0, TLS 0x0303, suite 0xCCA9, group 0x0017.

**L: REST latency** (the harness' `get_info` call every 0.5 s; 30 idle samples, 360 busy samples over 180 s of back-to-back TLS runs; milliseconds):

| | idle median / p95 / max | busy median / p95 / max | failures |
|---|---|---|---|
| Nios (`results/nios/L-nios.json`) | 9.88 / 10.87 / 11.06 | 20.74 / 27.45 / 90.14 | 0 / 360 |
| responder (`results/resp/L-resp.json`) | 10.04 / 10.56 / 10.60 | 10.78 / 21.51 / 29.97 | 0 / 360 |

**F: FTP download of the staged 4 MiB file** (KiB/s; 10 idle downloads, then back to back for 180 s busy):

| | idle median (min..max) | busy median (min..max) | busy downloads | failures |
|---|---|---|---|---|
| Nios (`results/niosF/F-nios.json`) | 1260.95 (1235.9..1271.8) | 610.1 (521.7..665.6) | 27 | 0 |
| responder (`results/respF/F-resp.json`) | 1250.7 (1232.7..1261.5) | 1019.8 (925.9..1105.0) | 45 | 0 |

Notes on the data:

- The first pass of the responder series was run by mistake at Turbo Off (1 MHz); it was discarded and is not included. It gave the same picture (handshake 1570 ms, transfer 2335 ms, REST busy median 11.3 ms).
- The Nios F series is `results/niosF/F-nios.json`. An earlier Nios F file from the A/L directory (a run with a non-zero exit code) is not used and not included.
- Under the FTP load a Nios handshake takes about 65 s instead of about 35 s, so only a few TLS runs fit into the 180 s window on the Nios image.

**What the packet captures showed** (taken on the peers' wired interface, filtered to the device and ports 18443/18444; not published, since a capture carries MAC addresses). Per-connection numbers derived with `capture_phase.py conns`: every TLS connection on every series negotiated `secp256r1`; every frame came from the device's Ethernet MAC (no WiFi path); the median ClientHello-to-client-ChangeCipherSpec time on the wire was 35.1 s for the Nios image (31 connections in the A, A-matched and L runs) and 1.35 s for the responder (66 connections); the median time from the client's `B` to the client's FIN was 7.18 s (Nios) and 2.33 s (responder), plain 267 ms and 275 ms. These agree with the device-side figures above. The capture's handshake figure ends at the client's ChangeCipherSpec, so it excludes the server's Finished and the last client step; use the device-side figures for comparison and the capture to confirm them.

## Not in this kit

The comparison on the real product path, a C64 program talking to the UCI, is not part of it: this kit has no 6510 program. The responder reproduces the command sequence of a C64 client from a Nios task precisely so that no C64 is involved. Test-suite runs of #997 (`net_tls_test`) are in the PR's own test tree.
