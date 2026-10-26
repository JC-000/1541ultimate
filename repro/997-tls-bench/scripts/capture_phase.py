#!/usr/bin/env python3
"""capture_phase.py: the phase clock of the matched TLS bench.

RECIPE (capture on the machine that runs the peers, on the wired port that faces the device; peers.sh does this when
CAPTURE_IFACE is set):

    dumpcap -i <iface> -f "host <device ip> and (tcp port 18443 or tcp port 18444)" -w capture.pcapng &   # stop it after the window

One capture covers the peer side, the probes and both builds, on one clock (the capture host's). Port 18443 is not a TLS
port to tshark, so every read here decodes it with `-d tcp.port==18443,tls`. The REST/FTP probes are NOT in this filter
(they would swamp it); their phase comes from the timestamps: the probe scripts stamp each sample with the Mac's wall
clock, which is the capture's clock. If the probes' own packets are wanted, widen the filter to `host <device ip>`.

USAGE
    capture_phase.py conns  capture.pcapng [--eth-mac <device MAC>] [--out conns.json]
        one record per connection: handshake / client compute / transfer / plain phases (ms), the ECDHE group from
        ServerKeyExchange, source MACs (with --eth-mac: mac_ok per connection; any other MAC = the run is INVALID)
    capture_phase.py tag    conns.json L-nios.json [--out L-nios.tagged.json]     (or an F json)
        adds `cap_phase` (phase at the sample's start) and `cap_phase_end` to every L sample, `cap_phase` to every F
        download (the phase covering >= 90 % of it, else "mixed"), and a per-phase summary.
    capture_phase.py selftest        (builds a synthetic pcap, runs tshark on it, checks every derived number)

PHASES (from the connections; a time outside every connection of the device is `gap`; before the first SYN of the
busy window the sample's own `phase` field says idle):
    tcp+hs          SYN .. ServerHelloDone  and  ClientKeyExchange .. client's first application record
    client_compute  ServerHelloDone .. ClientKeyExchange (where the P-256 / key work sits on the Nios)
    transfer        client 'B' .. client's ACK of the last TLS payload byte
    plain           the plain-TCP connection, SYN .. last ACK
    gap             everything else

COMMON TRANSFER YARDSTICK: xfer_fin_ms = client 'B' .. the CLIENT's FIN (same event on both builds and on the plain leg; the
client closes only after it consumed everything). xfer_ms (to the client's ACK of the last payload byte) is secondary: the two
builds ACK differently. data_to_fin_ms = last server payload .. client FIN.

NOTE hs_ms ends at the client's ChangeCipherSpec: it EXCLUDES the server's Finished and the client's last handshake step, and
the ESP build's x25519 key share is generated BEFORE ClientHello (so it sits outside hs_ms on that build only).
hello_to_app_ms (ClientHello .. 'B') is the second, whole-handshake figure that includes all of that; compare builds on it.

DERIVED PER TLS CONNECTION (ms): tcp_ms = SYN .. client's ACK of the SYN/ACK; hs_ms = ClientHello .. client's CCS
(the encrypted Finished follows it); client_compute_ms = ServerHelloDone .. ClientKeyExchange; xfer_ms = client 'B' ..
client ACK covering the last server application-data byte. Plain: xfer_ms the same on :18444.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

FIELDS = ["frame.number", "frame.time_epoch", "eth.src", "ip.src", "ip.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
          "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tls.record.content_type", "tls.handshake.type",
          "tls.handshake.server_named_curve"]
TLS_PORT, PLAIN_PORT = 18443, 18444
CURVES = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519"}


def tshark_rows(pcap):
    cmd = ["tshark", "-r", pcap, "-d", "tcp.port==%d,tls" % TLS_PORT, "-Y", "tcp", "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.exit("tshark failed: " + r.stderr[:500])
    rows = []
    for ln in r.stdout.splitlines():
        p = ln.split("\t")
        p += [""] * (len(FIELDS) - len(p))
        d = dict(zip(FIELDS, p))
        try:
            rows.append({"n": int(d["frame.number"]), "t": float(d["frame.time_epoch"]), "mac": d["eth.src"],
                         "src": d["ip.src"], "dst": d["ip.dst"], "stream": int(d["tcp.stream"]),
                         "sport": int(d["tcp.srcport"]), "dport": int(d["tcp.dstport"]),
                         "flags": int(d["tcp.flags"], 16), "seq": int(d["tcp.seq_raw"] or 0),
                         "ack": int(d["tcp.ack_raw"] or 0), "len": int(d["tcp.len"] or 0),
                         "ctype": [int(x) for x in d["tls.record.content_type"].split(",") if x],
                         "htype": [int(x) for x in d["tls.handshake.type"].split(",") if x],
                         "curve": [int(x, 16) if x.startswith("0x") else int(x)
                                   for x in d["tls.handshake.server_named_curve"].split(",") if x]})
        except ValueError:
            continue
    return rows


SYN, ACK, FIN = 0x02, 0x10, 0x01


def _first(rows, pred):
    for r in rows:
        if pred(r):
            return r
    return None


def connection(rows, device, eth_mac=None):
    """One stream's frames (time order) -> the phase record."""
    c2s = [r for r in rows if r["src"] == device]
    s2c = [r for r in rows if r["dst"] == device]
    port = rows[0]["dport"] if rows[0]["src"] == device else rows[0]["sport"]
    syn = _first(c2s, lambda r: r["flags"] & SYN and not r["flags"] & ACK)
    synack = _first(s2c, lambda r: r["flags"] & SYN and r["flags"] & ACK)
    ack3 = _first(c2s, lambda r: r["flags"] & ACK and not r["flags"] & SYN and synack and r["t"] >= synack["t"])
    rec = {"stream": rows[0]["stream"], "port": port, "kind": "tls" if port == TLS_PORT else "plain",
           "src_macs": sorted({r["mac"] for r in c2s if r["mac"]}), "frames": len(rows)}
    if eth_mac is not None:
        rec["mac_ok"] = rec["src_macs"] == [eth_mac.lower()]
    t = {}
    t["syn"] = syn["t"] if syn else None
    t["connected"] = ack3["t"] if ack3 else None
    if rec["kind"] == "tls":
        ch = _first(c2s, lambda r: 1 in r["htype"])
        shd = _first(s2c, lambda r: 14 in r["htype"])
        ckx = _first(c2s, lambda r: 16 in r["htype"])
        ccs = _first(c2s, lambda r: 20 in r["ctype"])
        app_c = _first(c2s, lambda r: 23 in r["ctype"])
        t["client_hello"] = ch["t"] if ch else None
        t["server_hello_done"] = shd["t"] if shd else None
        t["client_key_exchange"] = ckx["t"] if ckx else None
        t["client_ccs"] = ccs["t"] if ccs else None
        t["client_app"] = app_c["t"] if app_c else None
        ske = _first(s2c, lambda r: 12 in r["htype"] and r["curve"])
        if ske:
            g = ske["curve"][0]
            rec["group"] = "0x%04X" % g
            rec["group_name"] = CURVES.get(g, "?")
        app_s = [r for r in s2c if 23 in r["ctype"]]
        alert = _first(s2c, lambda r: 21 in r["ctype"] and (not app_s or r["t"] >= app_s[-1]["t"]))
        t["close_notify"] = alert["t"] if alert else None
        payload_frames = app_s
    else:
        data_c = _first(c2s, lambda r: r["len"] > 0)
        t["client_app"] = data_c["t"] if data_c else None
        payload_frames = [r for r in s2c if r["len"] > 0 and (data_c is None or r["t"] >= data_c["t"])]
    fin = _first(c2s, lambda r: r["flags"] & FIN)       # the CLIENT's (device's) FIN, not whichever side closed first
    t["fin"] = fin["t"] if fin else None
    if payload_frames:
        last = payload_frames[-1]
        end = max(r["seq"] + r["len"] for r in payload_frames)
        first_seq = min(r["seq"] for r in payload_frames)
        ack = _first(c2s, lambda r: r["flags"] & ACK and r["t"] >= last["t"] and (r["ack"] - end) % (1 << 32) < (1 << 31))
        t["last_server_payload"] = last["t"]
        t["last_ack"] = ack["t"] if ack else None
        rec["server_bytes"] = (end - first_seq) % (1 << 32)
    else:
        t["last_server_payload"] = t["last_ack"] = None
    rec["t"] = t

    def ms(a, b):
        return round((t[b] - t[a]) * 1000.0, 3) if t.get(a) is not None and t.get(b) is not None else None
    rec["tcp_ms"] = ms("syn", "connected")
    if rec["kind"] == "tls":
        rec["hs_ms"] = ms("client_hello", "client_ccs")
        rec["client_compute_ms"] = ms("server_hello_done", "client_key_exchange")
        rec["server_flight_ms"] = ms("client_hello", "server_hello_done")
    rec["xfer_ms"] = ms("client_app", "last_ack")                  # secondary: ACK-based
    rec["xfer_fin_ms"] = ms("client_app", "fin")                   # the common yardstick: client 'B' .. client FIN
    rec["data_to_fin_ms"] = ms("last_server_payload", "fin")
    if rec["kind"] == "tls":
        rec["hello_to_app_ms"] = ms("client_hello", "client_app")  # ClientHello .. 'B': whole handshake incl. the client's last step
    rec["total_ms"] = ms("syn", "fin") if t["fin"] is not None else ms("syn", "last_ack")
    return rec


def connections(pcap, device, eth_mac=None):
    rows = tshark_rows(pcap)
    streams = {}
    for r in rows:
        if device in (r["src"], r["dst"]) and (r["sport"] in (TLS_PORT, PLAIN_PORT) or r["dport"] in (TLS_PORT, PLAIN_PORT)):
            streams.setdefault(r["stream"], []).append(r)
    out = [connection(sorted(v, key=lambda r: r["n"]), device, eth_mac) for v in streams.values()]
    out.sort(key=lambda c: c["t"]["syn"] or 0)
    return out


# ---------------------------------------------------------------- tagging
def intervals(conns):
    """[(start, end, phase)] sorted; later entries win where they overlap (they do not within one connection)."""
    iv = []
    for c in conns:
        t = c["t"]
        if c["kind"] == "plain":
            end = t["last_ack"] or t["fin"] or t["syn"]
            if t["syn"] is not None:
                iv.append((t["syn"], end, "plain"))
            continue
        syn, shd, ckx, app, ack = t["syn"], t["server_hello_done"], t["client_key_exchange"], t["client_app"], t["last_ack"]
        if syn is None:
            continue
        if shd is not None:
            iv.append((syn, shd, "tcp+hs"))
        if shd is not None and ckx is not None:
            iv.append((shd, ckx, "client_compute"))
        if ckx is not None and app is not None:
            iv.append((ckx, app, "tcp+hs"))
        if app is not None and ack is not None:
            iv.append((app, ack, "transfer"))
    return sorted(iv)


def phase_at(iv, x):
    for a, b, name in iv:
        if a <= x <= b:
            return name
    return "gap"


def phase_of_span(iv, a, b):
    """The phase covering >= 90 % of [a, b], else 'mixed'."""
    if b <= a:
        return phase_at(iv, a)
    cover = {}
    for s, e, name in iv:
        o = min(b, e) - max(a, s)
        if o > 0:
            cover[name] = cover.get(name, 0.0) + o
    covered = sum(cover.values())
    cover["gap"] = max(0.0, (b - a) - covered)
    best = max(cover, key=cover.get)
    return best if cover[best] >= 0.9 * (b - a) else "mixed"


def tag(conns, series):
    iv = intervals(conns)
    busy = series.get("busy", [])
    idle = series.get("idle", [])
    per = {}
    for s in busy + idle:
        if "t_wall" in s:                                    # L samples
            start = s["t_wall"]
            end = start + (s["elapsed_ms"] or 0) / 1000.0
            s["cap_phase"] = phase_at(iv, start) if s.get("phase") != "idle" else "idle"
            s["cap_phase_end"] = phase_at(iv, end) if s.get("phase") != "idle" else "idle"
            key = s["cap_phase"]
            per.setdefault(key, []).append(s)
        else:                                                # F downloads
            s["cap_phase"] = phase_of_span(iv, s["start_wall"], s["end_wall"]) if s.get("phase") != "idle" else "idle"
            per.setdefault(s["cap_phase"], []).append(s)
    summ = {}
    for k, v in per.items():
        if v and "elapsed_ms" in v[0]:
            ok = [x for x in v if x["error"] is None]
            vals = sorted(x["elapsed_ms"] for x in ok)
            summ[k] = {"count": len(v), "failures": len(v) - len(ok),
                       "median_ms": _median(vals), "p95_ms": vals[int(0.95 * (len(vals) - 1))] if vals else None,
                       "max_ms": vals[-1] if vals else None}
        else:
            ok = [x for x in v if x.get("sha_ok")]
            vals = sorted(x["kib_s"] for x in ok if x["kib_s"] is not None)
            summ[k] = {"count": len(v), "failures": len(v) - len(ok), "median_kib_s": _median(vals),
                       "min_kib_s": vals[0] if vals else None}
    series["cap_phase_summary"] = summ
    return series


def _median(v):
    if not v:
        return None
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("conns")
    c.add_argument("pcap")
    c.add_argument("--device", default=os.environ.get("TLSB_HOST"), help="device IP in the capture (default: $TLSB_HOST)")
    c.add_argument("--eth-mac", default=os.environ.get("TLSB_ETH_MAC"), help="the device's Ethernet MAC (default: $TLSB_ETH_MAC); with it, a frame from any other source MAC (a WiFi path) makes the run INVALID")
    c.add_argument("--out")
    t = sub.add_parser("tag")
    t.add_argument("conns")
    t.add_argument("series")
    t.add_argument("--out")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        import test_capture_phase
        test_capture_phase.main()
        return 0
    if a.cmd == "conns":
        if not a.device:
            ap.error("no device address: pass --device or set TLSB_HOST")
        res = connections(a.pcap, a.device, a.eth_mac)
        text = json.dumps(res, indent=2)
        if a.out:
            open(a.out, "w").write(text + "\n")
        else:
            print(text)
        bad = [x["stream"] for x in res if x.get("mac_ok") is False]
        if bad:
            print("INVALID: streams %s have a source MAC other than --eth-mac (WiFi path?)" % bad, file=sys.stderr)
            return 3
        return 0
    conns = json.load(open(a.conns))
    series = json.load(open(a.series))
    tagged = tag(conns, series)
    out = a.out or a.series.replace(".json", ".tagged.json")
    open(out, "w").write(json.dumps(tagged, indent=2) + "\n")
    print(json.dumps(tagged["cap_phase_summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
