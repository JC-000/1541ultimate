#!/usr/bin/env python3
"""Synthetic-capture test for capture_phase.py: builds a pcap with hand-made TLS 1.2 records (one TLS run, one plain
run) at known times, runs the real tshark over it, and checks every derived number. No device, no network."""
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_phase as cp  # noqa: E402

DEV_MAC = bytes.fromhex("0200000000a1")        # locally administered, stands for the U64E's Ethernet MAC
MAC_MAC = bytes.fromhex("c05627b11638")
SYNTH_MAC = ":".join(("02", "00", "00", "00", "00", "a1"))   # the synthetic device MAC the pcap builder uses
DEV_IP, MAC_IP = bytes([192, 0, 2, 81]), bytes([192, 0, 2, 182])
T0 = 1_700_000_000.0


def hs(typ, body):
    return bytes([typ]) + len(body).to_bytes(3, "big") + body


def rec(ctype, body, ver=b"\x03\x03"):
    return bytes([ctype]) + ver + struct.pack(">H", len(body)) + body


CLIENT_HELLO = rec(22, hs(1, b"\x03\x03" + bytes(32) + b"\x00" + struct.pack(">H", 2) + b"\xcc\xa9" + b"\x01\x00" + b"\x00\x00"), b"\x03\x01")
SERVER_FLIGHT = (rec(22, hs(2, b"\x03\x03" + bytes(32) + b"\x00" + b"\xcc\xa9" + b"\x00" + b"\x00\x00"))
                 + rec(22, hs(11, b"\x00\x00\x00"))
                 + rec(22, hs(12, b"\x03\x00\x17" + b"\x41" + b"\x04" + bytes(64) + b"\x04\x03" + struct.pack(">H", 8) + bytes(8)))
                 + rec(22, hs(14, b"")))
CKX = rec(22, hs(16, b"\x41\x04" + bytes(64)))
CCS_FIN = rec(20, b"\x01") + rec(22, bytes(40))
SRV_CCS_FIN = rec(20, b"\x01") + rec(22, bytes(40))
APP_B = rec(23, bytes(17))
ALERT = rec(21, bytes(18))


class Pcap:
    def __init__(self):
        self.frames = []
        self.seq = {}

    def add(self, t, from_dev, sport, dport, flags, payload=b"", seq=None, ack=0):
        key = (from_dev, sport, dport)
        if seq is None:
            seq = self.seq.get(key, 1000 if from_dev else 5000)
        sip, dip = (DEV_IP, MAC_IP) if from_dev else (MAC_IP, DEV_IP)
        sp, dp = (sport, dport) if from_dev else (dport, sport)
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, sip, dip) + tcp
        eth = (MAC_MAC + DEV_MAC if from_dev else DEV_MAC + MAC_MAC) + b"\x08\x00" + ip
        self.frames.append((t, eth))
        adv = len(payload) + (1 if flags & 0x03 else 0)
        self.seq[key] = seq + adv
        return seq + adv

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, d in sorted(self.frames, key=lambda x: x[0]):
                sec = int(t)
                f.write(struct.pack("<IIII", sec, int(round((t - sec) * 1e6)), len(d), len(d)) + d)


def build(path, wifi_frame=False):
    p = Pcap()
    P = 40000
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    # ---- TLS connection (port 18443)
    p.add(T0 + 0.000, True, P, 18443, SYN)
    p.add(T0 + 0.001, False, P, 18443, SYN | ACK, ack=1001)
    p.add(T0 + 0.002, True, P, 18443, ACK, ack=5001)
    p.add(T0 + 0.010, True, P, 18443, PSH | ACK, CLIENT_HELLO, ack=5001)
    p.add(T0 + 0.012, False, P, 18443, PSH | ACK, SERVER_FLIGHT, ack=1001 + len(CLIENT_HELLO))
    p.add(T0 + 36.000, True, P, 18443, PSH | ACK, CKX, ack=5001 + len(SERVER_FLIGHT))
    p.add(T0 + 36.002, True, P, 18443, PSH | ACK, CCS_FIN, ack=5001 + len(SERVER_FLIGHT))
    p.add(T0 + 36.050, False, P, 18443, PSH | ACK, SRV_CCS_FIN)
    p.add(T0 + 36.060, True, P, 18443, PSH | ACK, APP_B)
    end = 0
    for i in range(3):
        end = p.add(T0 + 36.100 + 0.050 * i, False, P, 18443, PSH | ACK, rec(23, bytes(1000)))
    p.add(T0 + 36.250, True, P, 18443, ACK, ack=end)
    p.add(T0 + 36.260, False, P, 18443, PSH | ACK, ALERT)
    p.add(T0 + 36.270, True, P, 18443, FIN | ACK)
    p.add(T0 + 36.280, False, P, 18443, FIN | ACK)
    # ---- plain connection (port 18444)
    Q = 40001
    p.add(T0 + 38.000, True, Q, 18444, SYN)
    p.add(T0 + 38.001, False, Q, 18444, SYN | ACK)
    p.add(T0 + 38.003, True, Q, 18444, ACK)
    p.add(T0 + 38.010, True, Q, 18444, PSH | ACK, b"B")
    for i in range(3):
        end = p.add(T0 + 38.100 + 0.100 * i, False, Q, 18444, PSH | ACK, bytes(1400))
    p.add(T0 + 38.301, True, Q, 18444, ACK, ack=end)
    p.add(T0 + 38.302, False, Q, 18444, FIN | ACK)
    p.add(T0 + 38.303, True, Q, 18444, FIN | ACK)
    if wifi_frame:     # a frame of the TLS stream from another MAC: the run must be flagged
        p.frames.append((T0 + 36.31, p.frames[0][1][:6] + b"\x02\x00\x00\x00\x00\xb2" + p.frames[0][1][12:]))
    p.write(path)


def near(a, b, tol=0.01):
    assert a is not None and abs(a - b) <= tol, (a, b)


def main():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "synth.pcap")
    build(path)
    conns = cp.connections(path, "192.0.2.81", eth_mac=SYNTH_MAC)
    assert len(conns) == 2, conns
    tls, plain = conns
    assert tls["kind"] == "tls" and plain["kind"] == "plain"
    assert tls["group"] == "0x0017" and tls["group_name"] == "secp256r1", tls
    near(tls["tcp_ms"], 2.0)
    near(tls["server_flight_ms"], 2.0)
    near(tls["client_compute_ms"], 35988.0, 0.01)
    near(tls["hs_ms"], 35992.0, 0.01)
    near(tls["xfer_ms"], 190.0)          # 36.060 -> 36.250
    near(tls["xfer_fin_ms"], 210.0)      # 36.060 -> client FIN 36.270
    near(tls["data_to_fin_ms"], 70.0)    # last server payload 36.200 -> 36.270
    near(tls["hello_to_app_ms"], 36050.0)
    near(plain["xfer_fin_ms"], 293.0)    # server FIN came first (38.302); the CLIENT's is 38.303
    near(plain["total_ms"], 303.0)
    assert tls["mac_ok"] is True and plain["mac_ok"] is True
    near(plain["tcp_ms"], 3.0)
    near(plain["xfer_ms"], 291.0)        # 38.010 -> 38.301
    assert plain["server_bytes"] == 4200, plain["server_bytes"]
    near(tls["t"]["close_notify"], T0 + 36.260, 0.0005)
    # a stray MAC is flagged
    build(path, wifi_frame=True)
    bad = cp.connections(path, "192.0.2.81", eth_mac=SYNTH_MAC)
    assert any(c["mac_ok"] is False for c in bad)
    # tagging
    build(path)
    conns = cp.connections(path, "192.0.2.81")
    iv = cp.intervals(conns)
    assert cp.phase_at(iv, T0 + 0.005) == "tcp+hs"
    assert cp.phase_at(iv, T0 + 10.0) == "client_compute"
    assert cp.phase_at(iv, T0 + 36.01) == "tcp+hs"
    assert cp.phase_at(iv, T0 + 36.2) == "transfer"
    assert cp.phase_at(iv, T0 + 37.0) == "gap"
    assert cp.phase_at(iv, T0 + 38.2) == "plain"
    series = {"idle": [{"t_wall": T0 - 5, "elapsed_ms": 9.0, "error": None, "phase": "idle"}],
              "busy": [{"t_wall": T0 + 10.0, "elapsed_ms": 900.0, "error": None, "phase": "busy"},
                       {"t_wall": T0 + 36.15, "elapsed_ms": 30.0, "error": None, "phase": "busy"},
                       {"t_wall": T0 + 36.5, "elapsed_ms": 5000.0, "error": "timeout", "phase": "busy"},
                       {"start_wall": T0 + 5.0, "end_wall": T0 + 6.0, "sha_ok": True, "kib_s": 100.0, "phase": "busy"}]}
    # the F-style row has no t_wall: keep the L and F rows apart
    f_row = series["busy"].pop()
    out = cp.tag(conns, series)
    ph = [s["cap_phase"] for s in out["busy"]]
    assert ph == ["client_compute", "transfer", "gap"], ph
    assert out["idle"][0]["cap_phase"] == "idle"
    assert out["cap_phase_summary"]["transfer"]["count"] == 1 and out["cap_phase_summary"]["gap"]["failures"] == 1
    fs = cp.tag(conns, {"idle": [], "busy": [f_row, {"start_wall": T0 + 30.0, "end_wall": T0 + 40.0, "sha_ok": True,
                                                  "kib_s": 50.0, "phase": "busy"}]})
    assert [r["cap_phase"] for r in fs["busy"]] == ["client_compute", "mixed"], fs["busy"]
    # CLI conns path exit codes
    r = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture_phase.py"),
                        "conns", path, "--device", "192.0.2.81", "--eth-mac", SYNTH_MAC], capture_output=True, text=True)
    assert r.returncode == 0 and json.loads(r.stdout)[0]["group_name"] == "secp256r1", r.stderr
    build(path, wifi_frame=True)
    r = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture_phase.py"),
                        "conns", path, "--device", "192.0.2.81", "--eth-mac", SYNTH_MAC], capture_output=True, text=True)
    assert r.returncode == 3 and "INVALID" in r.stderr, (r.returncode, r.stderr)
    print("capture_phase selftest ok")


if __name__ == "__main__":
    main()
